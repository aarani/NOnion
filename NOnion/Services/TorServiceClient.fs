namespace NOnion.Services

open System
open System.Net
open System.Security.Cryptography
open System.Text

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
open NOnion.Network
open NOnion.Http
open System.Linq

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
        (url: string)
        =
        TorServiceClient.Connect directory url |> Async.StartAsTask

    static member Connect
        (directory: TorDirectory)
        (url: string)
        =
        async {
            let! networkStatus = directory.GetLiveNetworkStatus()
            
            let periodNum, periodLength = networkStatus.GetTimePeriod()
            let srv = networkStatus.GetCurrentSRV()
            let publicKey = HSUtility.getPublicKeyFromUrl url
            let blindedPublicKey =
                HiddenServicesCipher.BuildBlindedPublicKey (periodNum, periodLength) publicKey
            
            let hsdir_n_replicas = 2
            let hsdir_spread_fetch = 3
            let hsdir_spread_store = 4
            
            let Compare (x:byte[]) (y:byte[]) =
                let xlen = x.Length
                let ylen = y.Length
                let len = if xlen<ylen then xlen else ylen
                let mutable i = 0
                let mutable result = 0
                while i<len do
                    let c = (int (x.[i])) - int (y.[i])
                    if c <> 0 then
                        i <- len+1 // breaks out of the loop, and signals that result is valid
                        result <- c
                    else
                        i <- i + 1
                if i>len then result else (xlen - ylen)
            
            let directories = 
                networkStatus.GetHSDirectories()
                |> List.choose (fun node ->
                        try
                            (node.GetIdentity(),
                            Array.concat 
                                [
                                    "node-idx" |> Encoding.ASCII.GetBytes;
                                    (node.GetIdentity() |> directory.GetDescriptorByIdentity).MasterKeyEd25519.Value |> Base64Util.FromString
                                    srv |> Convert.FromBase64String;
                                    periodNum |> IntegerSerialization.FromUInt64ToBigEndianByteArray;
                                    periodLength |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                ] |> HiddenServicesCipher.SHA3256)
                            |> Some
                        with
                        | _ -> None
                    )
                |> List.sortWith (fun (_,idx1) (_,idx2) -> Compare idx1 idx2 )
            
            let rec getRoutersToFetch (replicaNum: int) (state: list<string>)=
                if replicaNum > hsdir_n_replicas then
                    state
                else
                    let hs_index =
                        Array.concat 
                            [
                                "store-at-idx" |> Encoding.ASCII.GetBytes
                                blindedPublicKey
                                replicaNum |> uint64 |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                periodLength |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                periodNum |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            ] |> HiddenServicesCipher.SHA3256
                    //FIXME: binary serach idx here

                    let start = 
                        directories
                        |> Seq.tryFindIndex (fun (_, index) -> Compare index hs_index >= 0)
                        |> Option.defaultValue 0
                    let mutable idx = start
                    let mutable nodes = state
                    let mutable n_added = 0
                    let mutable n_to_add = hsdir_spread_fetch
                    while n_added < n_to_add do
                        let node = fst directories.[idx]
                        if not (nodes |> Seq.contains node) then
                            nodes <- nodes @ [node]
                            n_added <- n_added + 1
                        idx <- idx + 1
                        if idx = directories.Length then
                            idx <- 0
                        if idx = start then
                            n_added <- n_to_add + 1
                    getRoutersToFetch (replicaNum + 1) nodes

            let routersToFetch = getRoutersToFetch 1 List.empty
            let router = routersToFetch |> SeqUtils.TakeRandom 1 |> Seq.exactlyOne 
            let circuitNode = router |> directory.GetCircuitNodeDetailByIdentity
            
            let! endPoint, randomNodeDetails =
                directory.GetRouter RouterType.Guard
            let! _, randomNodeDetails2 =
                directory.GetRouter RouterType.Normal

            let! guard = TorGuard.NewClient endPoint

            let circuit = TorCircuit(guard)
            do! circuit.Create(randomNodeDetails) |> Async.Ignore
            do! circuit.Extend(randomNodeDetails2) |> Async.Ignore
            do! circuit.Extend(circuitNode) |> Async.Ignore
            let dirStream = TorStream(circuit)
            do! dirStream.ConnectToDirectory() |> Async.Ignore

            let! test = TorHttpClient(dirStream, "127.0.0.1").GetAsString (sprintf "/tor/hs/3/%s" ((Convert.ToBase64String blindedPublicKey))) false
            let test2 = HiddenServiceFirstLayerDescriptorDocument.Parse test
            let salt = test2.EncryptedPayload.Value |> Array.take 16
            let encrypted = test2.EncryptedPayload.Value |> Array.skip 16 |> Array.take (test2.EncryptedPayload.Value.Length - 48)
            let mac = test2.EncryptedPayload.Value |> Array.skip (test2.EncryptedPayload.Value.Length - 32)
            let secretInput =
                Array.concat
                    [
                        blindedPublicKey
                        HiddenServicesCipher.GetSubCredential (periodNum, periodLength) publicKey
                        test2.RevisionCounter.Value |> uint64 |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                    ]
            let stringConstant = "hsdir-superencrypted-data" |> Encoding.ASCII.GetBytes

            let keys =
                Array.concat 
                    [
                        secretInput
                        salt
                        stringConstant
                    ] |> HiddenServicesCipher.CalculateShake256 (32+16+32)
            let SECRET_KEY = keys |> Array.take 32
            let SECRET_IV = keys |> Array.skip 32 |> Array.take 16
            let MAC_KEY = keys |> Array.skip 48  |> Array.take 32
            let computedMac =
                Array.concat
                    [
                        MAC_KEY.Length |> uint64 |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                        MAC_KEY
                        salt.Length |> uint64 |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                        salt
                        encrypted
                    ] |> HiddenServicesCipher.SHA3256
            assert (Enumerable.SequenceEqual(computedMac, mac))
            let test3 = (TorStreamCipher(SECRET_KEY,Some SECRET_IV).Encrypt encrypted |> Encoding.ASCII.GetString).Trim('\000')
            let test3Parsed = HiddenServiceSecondLayerDescriptorDocument.Parse test3
            let salt2 = test3Parsed.EncryptedPayload.Value |> Array.take 16
            let encrypted2 = test3Parsed.EncryptedPayload.Value |> Array.skip 16 |> Array.take (test3Parsed.EncryptedPayload.Value.Length - 48)
            let mac2 = test3Parsed.EncryptedPayload.Value |> Array.skip (test3Parsed.EncryptedPayload.Value.Length - 32)

            let keys2 =
                Array.concat 
                    [
                        secretInput
                        salt2
                        "hsdir-encrypted-data" |> Encoding.ASCII.GetBytes
                    ] |> HiddenServicesCipher.CalculateShake256 (32+16+32)
            let SECRET_KEY = keys2 |> Array.take 32
            let SECRET_IV = keys2 |> Array.skip 32 |> Array.take 16
            let MAC_KEY = keys2 |> Array.skip 48  |> Array.take 32

            let computedMac =
                Array.concat
                    [
                        MAC_KEY.Length |> uint64 |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                        MAC_KEY
                        salt2.Length |> uint64 |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                        salt2
                        encrypted2
                    ] |> HiddenServicesCipher.SHA3256

            assert (Enumerable.SequenceEqual(computedMac, mac2))
            let test4 = (TorStreamCipher(SECRET_KEY,Some SECRET_IV).Encrypt encrypted2 |> Encoding.ASCII.GetString).Trim('\000')
            let test5 = HiddenServiceDescriptorDocument.Parse test4

            let introductionPoint = test5.IntroductionPoints |> SeqUtils.TakeRandom 1 |> Seq.exactlyOne

            let authKeyBytes =
                use memStream = new System.IO.MemoryStream (introductionPoint.AuthKey.Value)
                use binaryReader = new System.IO.BinaryReader (memStream)
                let certficate = Certificate.Deserialize binaryReader
                certficate.CertifiedKey

            let introductionPointAuthKey = Ed25519PublicKeyParameters(authKeyBytes, 0)
            let introductionPointEncKey = X25519PublicKeyParameters(introductionPoint.EncKey.Value, 0)


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

                let data, macKey =
                    HiddenServicesCipher.EncryptIntroductionData
                        (introduceInnerData.ToBytes())
                        randomPrivateKey
                        randomPublicKey
                        introductionPointAuthKey
                        introductionPointEncKey
                        (periodNum, periodLength)
                        publicKey

                let introduce1Packet =
                    let introduce1PacketForMac =
                        {
                            RelayIntroduce.AuthKey =
                                RelayIntroAuthKey.ED25519SHA3256(
                                    authKeyBytes
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

                let introductionPointNodeDetail =
                    use memStream = new System.IO.MemoryStream(introductionPoint.LinkSpecifiers.Value)
                    use reader = new System.IO.BinaryReader (memStream)
                    let rec readLinkSpecifier (n: byte) (state: List<LinkSpecifier>) =
                        if n = 0uy then
                            state
                        else
                            LinkSpecifier.Deserialize reader
                            |> List.singleton
                            |> List.append state
                            |> readLinkSpecifier(n - 1uy)

                    let linkSpecifiers = readLinkSpecifier(reader.ReadByte()) List.empty
                    let endpointSpecifier =
                        (linkSpecifiers
                        |> List.find (fun ls -> ls.Type = LinkSpecifierType.TLSOverTCPV4)).ToEndPoint()
                    let identityKey =
                        (linkSpecifiers
                        |> Seq.find (fun ls -> ls.Type = LinkSpecifierType.LegacyIdentity)).Data

                    CircuitNodeDetail.Create(endpointSpecifier, introductionPoint.OnionKey.Value, identityKey)

                let introCircuit = TorCircuit rendezvousGuard

                do! introCircuit.Create guardnode |> Async.Ignore
                do! introCircuit.Extend introductionPointNodeDetail |> Async.Ignore

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
