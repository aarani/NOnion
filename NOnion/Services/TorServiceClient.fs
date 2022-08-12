﻿namespace NOnion.Services

open System
open System.IO
open System.Net
open System.Security.Cryptography
open System.Text
open System.Linq

open Org.BouncyCastle.Crypto.Agreement
open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

open NOnion
open NOnion.Cells.Relay
open NOnion.Crypto
open NOnion.Utility
open NOnion.Directory
open NOnion.Http
open NOnion.Network

type TorServiceDescriptors =
    | OnionURL of string
    | NOnion of IntroductionPointPublicInfo

    member self.GetConnectionInfo(directory: TorDirectory) =
        async {
            match self with
            | NOnion connectionDetail ->
                return
                    Ed25519PublicKeyParameters(
                        connectionDetail.AuthKey |> Convert.FromBase64String,
                        0
                    ),
                    X25519PublicKeyParameters(
                        connectionDetail.EncryptionKey
                        |> Convert.FromBase64String,
                        0
                    ),
                    CircuitNodeDetail.Create(
                        IPEndPoint(
                            IPAddress.Parse(connectionDetail.Address),
                            connectionDetail.Port
                        ),
                        connectionDetail.OnionKey |> Convert.FromBase64String,
                        connectionDetail.Fingerprint |> Convert.FromBase64String
                    ),
                    connectionDetail.MasterPublicKey |> Convert.FromBase64String
            | OnionURL url ->
                let! networkStatus = directory.GetLiveNetworkStatus()

                let periodNum, periodLength = networkStatus.GetTimePeriod()
                let srv = networkStatus.GetCurrentSRV()

                let publicKey = HSUtility.GetPublicKeyFromUrl url

                let blindedPublicKey =
                    HiddenServicesCipher.BuildBlindedPublicKey
                        (periodNum, periodLength)
                        publicKey

                let ByteArrayCompare (x: array<byte>) (y: array<byte>) =
                    let xlen = x.Length
                    let ylen = y.Length

                    let len =
                        if xlen < ylen then
                            xlen
                        else
                            ylen

                    let mutable index = 0
                    let mutable result = 0

                    while index < len do
                        let diff = (int(x.[index])) - int(y.[index])

                        if diff <> 0 then
                            index <- len + 1 // breaks out of the loop, and signals that result is valid
                            result <- diff
                        else
                            index <- index + 1

                    if index > len then
                        result
                    else
                        (xlen - ylen)

                let directories =
                    networkStatus.GetHSDirectories()
                    |> List.choose(fun node ->
                        try
                            (node.GetIdentity(),
                             Array.concat
                                 [
                                     "node-idx" |> Encoding.ASCII.GetBytes
                                     (node.GetIdentity()
                                      |> directory.GetDescriptorByIdentity)
                                         .MasterKeyEd25519
                                         .Value
                                     |> Base64Util.FromString
                                     srv |> Convert.FromBase64String
                                     periodNum
                                     |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                     periodLength
                                     |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                 ]
                             |> HiddenServicesCipher.SHA3256)
                            |> Some
                        with
                        | _ -> None
                    )
                    |> List.sortWith(fun (_, idx1) (_, idx2) ->
                        ByteArrayCompare idx1 idx2
                    )

                let rec getRoutersToFetch
                    (replicaNum: int)
                    (state: list<string>)
                    =
                    if replicaNum > Constants.HsDirNReplicas then
                        state
                    else
                        let hsIndex =
                            Array.concat
                                [
                                    "store-at-idx" |> Encoding.ASCII.GetBytes
                                    blindedPublicKey
                                    replicaNum
                                    |> uint64
                                    |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                    periodLength
                                    |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                    periodNum
                                    |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                ]
                            |> HiddenServicesCipher.SHA3256

                        //FIXME: binary serach idx here
                        let start =
                            directories
                            |> Seq.tryFindIndex(fun (_, index) ->
                                ByteArrayCompare index hsIndex >= 0
                            )
                            |> Option.defaultValue 0

                        let rec pickNodes startIndex nToAdd state =
                            if nToAdd = 0 then
                                state
                            else
                                let node = fst directories.[startIndex]

                                let nextIndex =
                                    let idx = startIndex + 1

                                    if idx = directories.Length then
                                        0
                                    else
                                        idx

                                if not(state |> Seq.contains node) then
                                    if nextIndex = start then
                                        node :: state
                                    else
                                        pickNodes
                                            nextIndex
                                            (nToAdd - 1)
                                            (node :: state)
                                else if nextIndex = start then
                                    state
                                else
                                    pickNodes nextIndex nToAdd state

                        getRoutersToFetch
                            (replicaNum + 1)
                            (pickNodes start Constants.HsDirSpreadFetch state)

                let hsDirectoryNodeOpt =
                    getRoutersToFetch 1 List.empty
                    |> SeqUtils.TakeRandom 1
                    |> Seq.tryExactlyOne
                    |> Option.map directory.GetCircuitNodeDetailByIdentity

                match hsDirectoryNodeOpt with
                | None ->
                    return
                        failwith
                            "BUG: TorServiceClient::getRoutersToFetch returned empty list"
                | Some hsDirectoryNode ->
                    let! guardEndPoint, randomGuardNode =
                        directory.GetRouter RouterType.Guard

                    let! _, randomMiddleNode =
                        directory.GetRouter RouterType.Normal

                    let! guardNode = TorGuard.NewClient guardEndPoint
                    let circuit = TorCircuit guardNode
                    do! circuit.Create randomGuardNode |> Async.Ignore
                    do! circuit.Extend randomMiddleNode |> Async.Ignore
                    do! circuit.Extend hsDirectoryNode |> Async.Ignore

                    let dirStream = TorStream circuit
                    do! dirStream.ConnectToDirectory() |> Async.Ignore

                    let! firstLayerDescriptorDocument =
                        async {
                            let! documentInString =
                                TorHttpClient(
                                    dirStream,
                                    "127.0.0.1"
                                )
                                    .GetAsString
                                    (sprintf
                                        "/tor/hs/3/%s"
                                        ((Convert.ToBase64String
                                            blindedPublicKey)))
                                    false

                            return
                                HiddenServiceFirstLayerDescriptorDocument.Parse
                                    documentInString
                        }

                    let readEncryptedPayload(encryptedPayload: array<byte>) =
                        encryptedPayload |> Array.take 16,
                        encryptedPayload
                        |> Array.skip 16
                        |> Array.take(encryptedPayload.Length - 48),
                        encryptedPayload
                        |> Array.skip(encryptedPayload.Length - 32)

                    let getDecryptionKeys(input: array<byte>) =
                        let keyBytes =
                            input
                            |> HiddenServicesCipher.CalculateShake256(
                                Constants.KeyS256Length
                                + Constants.IVS256Length
                                + 32
                            )

                        keyBytes |> Array.take Constants.KeyS256Length,
                        keyBytes
                        |> Array.skip Constants.KeyS256Length
                        |> Array.take Constants.IVS256Length,
                        keyBytes
                        |> Array.skip(
                            Constants.KeyS256Length + Constants.IVS256Length
                        )
                        |> Array.take 32

                    let decryptDocument
                        (key: array<byte>)
                        (iv: array<byte>)
                        (encryptedData: array<byte>)
                        (parser: string -> 'T)
                        =
                        (TorStreamCipher(key, Some iv)
                            .Encrypt encryptedData
                         |> Encoding.ASCII.GetString)
                            .Trim('\000')
                        |> parser

                    let firstLayerSalt, firstLayerEncryptedData, firstLayerMac =
                        readEncryptedPayload
                            firstLayerDescriptorDocument.EncryptedPayload.Value

                    let secretInput =
                        Array.concat
                            [
                                blindedPublicKey
                                HiddenServicesCipher.GetSubCredential
                                    (periodNum, periodLength)
                                    publicKey
                                firstLayerDescriptorDocument.RevisionCounter.Value
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            ]

                    let (firstLayerDecryptionKey,
                         firstLayerDecryptionIV,
                         firstLayerDecryptionMacKey) =
                        Array.concat
                            [
                                secretInput
                                firstLayerSalt
                                Constants.HSDirEncryption.SuperEncrypted
                                |> Encoding.ASCII.GetBytes
                            ]
                        |> getDecryptionKeys

                    let computedFirstLayerMac =
                        Array.concat
                            [
                                firstLayerDecryptionMacKey.Length
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                firstLayerDecryptionMacKey
                                firstLayerSalt.Length
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                firstLayerSalt
                                firstLayerEncryptedData
                            ]
                        |> HiddenServicesCipher.SHA3256

                    if
                        not
                            (
                                Enumerable.SequenceEqual(
                                    computedFirstLayerMac,
                                    firstLayerMac
                                )
                            )
                    then
                        failwith "First layer mac is not correct"

                    let (secondLayerSalt,
                         secondLayerEncryptedData,
                         secondLayerMac) =
                        let secondLayerDescriptorDocument =
                            decryptDocument
                                firstLayerDecryptionKey
                                firstLayerDecryptionIV
                                firstLayerEncryptedData
                                HiddenServiceSecondLayerDescriptorDocument.Parse

                        readEncryptedPayload
                            secondLayerDescriptorDocument.EncryptedPayload.Value

                    let (secondLayerDecryptionKey,
                         secondLayerDecryptionIV,
                         secondLayerDecryptionMacKey) =
                        Array.concat
                            [
                                secretInput
                                secondLayerSalt
                                Constants.HSDirEncryption.Encrypted
                                |> Encoding.ASCII.GetBytes
                            ]
                        |> getDecryptionKeys

                    let computedSecondLayerMac =
                        Array.concat
                            [
                                secondLayerDecryptionMacKey.Length
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                secondLayerDecryptionMacKey
                                secondLayerSalt.Length
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                secondLayerSalt
                                secondLayerEncryptedData
                            ]
                        |> HiddenServicesCipher.SHA3256

                    if
                        not
                            (
                                Enumerable.SequenceEqual(
                                    computedSecondLayerMac,
                                    secondLayerMac
                                )
                            )
                    then
                        failwith "Second layer mac is not correct"

                    let hiddenServiceDescriptorDocument =
                        decryptDocument
                            secondLayerDecryptionKey
                            secondLayerDecryptionIV
                            secondLayerEncryptedData
                            HiddenServiceDescriptorDocument.Parse

                    let introductionPointOpt =
                        hiddenServiceDescriptorDocument.IntroductionPoints
                        |> SeqUtils.TakeRandom 1
                        |> Seq.tryExactlyOne

                    match introductionPointOpt with
                    | None ->
                        return failwith "HS's introduction point list was empty"
                    | Some introductionPoint ->
                        let introductionPointAuthKey =
                            let authKeyBytes =
                                use memStream =
                                    new System.IO.MemoryStream(
                                        introductionPoint.AuthKey.Value
                                    )

                                use binaryReader =
                                    new System.IO.BinaryReader(memStream)

                                let certficate =
                                    Certificate.Deserialize binaryReader

                                certficate.CertifiedKey

                            Ed25519PublicKeyParameters(authKeyBytes, 0)

                        let introductionPointEncKey =
                            X25519PublicKeyParameters(
                                introductionPoint.EncKey.Value,
                                0
                            )

                        let introductionPointNodeDetail =
                            use memStream =
                                new MemoryStream(
                                    introductionPoint.LinkSpecifiers.Value
                                )

                            use reader = new BinaryReader(memStream)

                            let rec readLinkSpecifier
                                (remainingLinkSpecifiers: int)
                                (state: List<LinkSpecifier>)
                                =
                                if remainingLinkSpecifiers = 0 then
                                    state
                                else
                                    LinkSpecifier.Deserialize reader
                                    |> List.singleton
                                    |> List.append state
                                    |> readLinkSpecifier(
                                        remainingLinkSpecifiers - 1
                                    )

                            let linkSpecifiers =
                                readLinkSpecifier
                                    (reader.ReadByte() |> int)
                                    List.empty

                            let endpointSpecifierOpt =
                                linkSpecifiers
                                |> List.tryFind(fun linkSpecifier ->
                                    linkSpecifier.Type = LinkSpecifierType.TLSOverTCPV4
                                )
                                |> Option.map(fun linkSpecifier ->
                                    linkSpecifier.ToEndPoint()
                                )

                            match endpointSpecifierOpt with
                            | None ->
                                failwith
                                    "Introduction point didn't have an IPV4 endpoint"
                            | Some endpointSpecifier ->
                                let identityKeyOpt =
                                    linkSpecifiers
                                    |> Seq.tryFind(fun linkSpecifier ->
                                        linkSpecifier.Type = LinkSpecifierType.LegacyIdentity
                                    )
                                    |> Option.map(fun linkSpecifier ->
                                        linkSpecifier.Data
                                    )

                                match identityKeyOpt with
                                | None ->
                                    failwith
                                        "Introduction point didn't have a legacy identity"
                                | Some identityKey ->
                                    CircuitNodeDetail.Create(
                                        endpointSpecifier,
                                        introductionPoint.OnionKey.Value,
                                        identityKey
                                    )

                        return
                            introductionPointAuthKey,
                            introductionPointEncKey,
                            introductionPointNodeDetail,
                            publicKey
        }


type TorServiceClient =
    private
        {
            RendezvousGuard: TorGuard
            RendezvousCircuit: TorCircuit
            Stream: TorStream
        }

    member self.GetStream() =
        self.Stream

    static member ConnectAsync
        (directory: TorDirectory)
        (connectionDetail: TorServiceDescriptors)
        =
        TorServiceClient.Connect directory connectionDetail |> Async.StartAsTask

    static member Connect
        (directory: TorDirectory)
        (connectionDetail: TorServiceDescriptors)
        =
        async {
            let! introductionPointAuthKey,
                 introductionPointEncKey,
                 introductionPointNodeDetail,
                 pubKey = connectionDetail.GetConnectionInfo directory

            let randomGeneratedCookie =
                Array.zeroCreate Constants.RendezvousCookieLength

            RandomNumberGenerator
                .Create()
                .GetNonZeroBytes randomGeneratedCookie

            let! endpoint, guardnode = directory.GetRouter RouterType.Guard
            let! _, rendezvousNode = directory.GetRouter RouterType.Normal

            let! rendezvousGuard = TorGuard.NewClient endpoint
            let rendezvousCircuit = TorCircuit rendezvousGuard

            do! rendezvousCircuit.Create guardnode |> Async.Ignore
            do! rendezvousCircuit.Extend rendezvousNode |> Async.Ignore

            do!
                rendezvousCircuit.RegisterAsRendezvousPoint
                    randomGeneratedCookie

            let randomPrivateKey, randomPublicKey =
                let kpGen = X25519KeyPairGenerator()
                let random = SecureRandom()
                kpGen.Init(X25519KeyGenerationParameters random)
                let keyPair = kpGen.GenerateKeyPair()

                keyPair.Private :?> X25519PrivateKeyParameters,
                keyPair.Public :?> X25519PublicKeyParameters

            match rendezvousNode with
            | Create(address, onionKey, identityKey) ->
                let introduceInnerData =
                    {
                        RelayIntroduceInnerData.OnionKey = onionKey
                        RendezvousCookie = randomGeneratedCookie
                        Extensions = List.empty
                        RendezvousLinkSpecifiers =
                            [
                                LinkSpecifier.CreateFromEndPoint address
                                {
                                    LinkSpecifier.Type =
                                        LinkSpecifierType.LegacyIdentity
                                    Data = identityKey
                                }
                            ]
                    }

                let! networkStatus = directory.GetLiveNetworkStatus()
                let periodInfo = networkStatus.GetTimePeriod()

                let data, macKey =
                    HiddenServicesCipher.EncryptIntroductionData
                        (introduceInnerData.ToBytes())
                        randomPrivateKey
                        randomPublicKey
                        introductionPointAuthKey
                        introductionPointEncKey
                        periodInfo
                        pubKey

                let introduce1Packet =
                    let introduce1PacketForMac =
                        {
                            RelayIntroduce.AuthKey =
                                RelayIntroAuthKey.ED25519SHA3256(
                                    introductionPointAuthKey.GetEncoded()
                                )
                            Extensions = List.empty
                            ClientPublicKey = randomPublicKey.GetEncoded()
                            Mac = Array.empty
                            EncryptedData = data
                        }

                    { introduce1PacketForMac with
                        Mac =
                            introduce1PacketForMac.ToBytes()
                            |> HiddenServicesCipher.CalculateMacWithSHA3256
                                macKey
                    }

                let introCircuit = TorCircuit rendezvousGuard

                do! introCircuit.Create guardnode |> Async.Ignore

                do!
                    introCircuit.Extend introductionPointNodeDetail
                    |> Async.Ignore

                let rendezvousJoin =
                    rendezvousCircuit.WaitingForRendezvousJoin
                        randomPrivateKey
                        randomPublicKey
                        introductionPointAuthKey
                        introductionPointEncKey

                let introduceJob =
                    async {
                        let! ack = introCircuit.Introduce introduce1Packet

                        if ack.Status <> RelayIntroduceStatus.Success then
                            return
                                failwithf
                                    "Unsuccessful introduction: %A"
                                    ack.Status
                    }

                do!
                    Async.Parallel [ introduceJob; rendezvousJoin ]
                    |> Async.Ignore

                let serviceStream = TorStream rendezvousCircuit
                do! serviceStream.ConnectToService() |> Async.Ignore

                return
                    {
                        RendezvousGuard = rendezvousGuard
                        RendezvousCircuit = rendezvousCircuit
                        Stream = serviceStream
                    }
            | _ -> return failwith "wat?"
        }

    interface IDisposable with
        member self.Dispose() =
            (self.RendezvousGuard :> IDisposable).Dispose()
