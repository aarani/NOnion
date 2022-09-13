namespace NOnion.Services

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Security.Cryptography
open System.Text
open System.Threading
open FSharpx.Collections

open Chaos.NaCl
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Security

open NOnion
open NOnion.Cells.Relay
open NOnion.Crypto
open NOnion.Directory
open NOnion.Utility
open NOnion.Network
open NOnion.Http

type IntroductionPointInfo =
    {
        Address: IPEndPoint
        EncryptionKey: AsymmetricCipherKeyPair
        AuthKey: AsymmetricCipherKeyPair
        MasterPublicKey: array<byte>
        OnionKey: array<byte>
        Fingerprint: array<byte>
    }

type TorServiceHost
    (
        directory: TorDirectory,
        maxDescriptorUploadRetryCount: int,
        maxRendezvousConnectRetryCount: int,
        maybeMasterPrivateKey: Option<Ed25519PrivateKeyParameters>
    ) =

    let mutable introductionPointKeys: Map<string, IntroductionPointInfo> =
        Map.empty

    let mutable guardNode: List<TorGuard> = List.empty
    let introductionPointSemaphore: SemaphoreLocker = SemaphoreLocker()
    let newClientSemaphore = new SemaphoreSlim(0)

    let masterPrivateKey, masterPublicKey =
        let masterPrivateKey =
            match maybeMasterPrivateKey with
            | Some masterPrivateKey when not(isNull masterPrivateKey) ->
                masterPrivateKey
            | _ ->
                let keyPair =
                    let kpGen = Ed25519KeyPairGenerator()
                    let random = SecureRandom()

                    kpGen.Init(Ed25519KeyGenerationParameters random)

                    kpGen.GenerateKeyPair()

                keyPair.Private :?> Ed25519PrivateKeyParameters

        masterPrivateKey, masterPrivateKey.GeneratePublicKey()

    let descriptorSigningPublicKey, descriptorSigningPrivateKey =
        let keyPair =
            let kpGen = Ed25519KeyPairGenerator()
            let random = SecureRandom()

            kpGen.Init(Ed25519KeyGenerationParameters random)
            kpGen.GenerateKeyPair()

        keyPair.Public :?> Ed25519PublicKeyParameters,
        keyPair.Private :?> Ed25519PrivateKeyParameters

    let mutable pendingConnectionQueue: Queue<uint16 * TorCircuit> = Queue.empty
    let queueLock: SemaphoreLocker = SemaphoreLocker()

    member private self.IncomingServiceStreamCallback
        (streamId: uint16)
        (senderCircuit: TorCircuit)
        =
        async {
            let registerConnectionRequest() =
                pendingConnectionQueue <-
                    pendingConnectionQueue.Conj(streamId, senderCircuit)

                newClientSemaphore.Release() |> ignore<int>

            queueLock.RunSyncWithSemaphore registerConnectionRequest
        }

    member private self.RelayIntroduceCallback(introduce: RelayIntroduce) =
        let rec tryConnectingToRendezvous
            rendezvousEndpoint
            rendezvousFingerPrint
            onionKey
            cookie
            clientPubKey
            introAuthPubKey
            introEncPrivKey
            introEncPubKey
            =
            async {
                let! endPoint, randomNodeDetails =
                    directory.GetRouter RouterType.Guard

                let! guard = TorGuard.NewClient endPoint

                let rendezvousCircuit =
                    TorCircuit(guard, self.IncomingServiceStreamCallback)

                do! rendezvousCircuit.Create randomNodeDetails |> Async.Ignore

                do!
                    rendezvousCircuit.Extend(
                        CircuitNodeDetail.Create(
                            rendezvousEndpoint,
                            onionKey,
                            rendezvousFingerPrint
                        )
                    )
                    |> Async.Ignore

                do!
                    rendezvousCircuit.Rendezvous
                        cookie
                        (X25519PublicKeyParameters(clientPubKey, 0))
                        introAuthPubKey
                        introEncPrivKey
                        introEncPubKey
            }

        async {
            let introductionPointDetails =
                match introduce.AuthKey with
                | RelayIntroAuthKey.ED25519SHA3256 bytes ->
                    match
                        introductionPointKeys.TryGetValue
                            (Convert.ToBase64String bytes)
                        with
                    | false, _ -> failwith "Unknown introduction point"
                    | true, details -> details
                | _ -> failwith "Unreachable, legacy keys are not implemented"

            let introAuthPubKey =
                introductionPointDetails.AuthKey.Public
                :?> Ed25519PublicKeyParameters

            let introEncPubKey =
                introductionPointDetails.EncryptionKey.Public
                :?> X25519PublicKeyParameters

            let introEncPrivKey =
                introductionPointDetails.EncryptionKey.Private
                :?> X25519PrivateKeyParameters

            let! networkStatus = directory.GetLiveNetworkStatus()
            let periodInfo = networkStatus.GetTimePeriod()

            let decryptedData, macKey =
                HiddenServicesCipher.DecryptIntroductionData
                    introduce.EncryptedData
                    (X25519PublicKeyParameters(introduce.ClientPublicKey, 0))
                    (introductionPointDetails.AuthKey.Public
                    :?> Ed25519PublicKeyParameters)
                    (introductionPointDetails.EncryptionKey.Private
                    :?> X25519PrivateKeyParameters)
                    (introductionPointDetails.EncryptionKey.Public
                    :?> X25519PublicKeyParameters)
                    periodInfo
                    introductionPointDetails.MasterPublicKey

            use decryptedStream = new MemoryStream(decryptedData)
            use decryptedReader = new BinaryReader(decryptedStream)
            let innerData = RelayIntroduceInnerData.Deserialize decryptedReader

            let digest =
                let introduceForMac =
                    { introduce with
                        Mac = Array.empty
                    }

                introduceForMac.ToBytes()
                |> HiddenServicesCipher.CalculateMacWithSHA3256 macKey

            if digest <> introduce.Mac then
                failwith "Invalid mac"

            let rendezvousEndpoint =
                let linkSpecifierOpt =
                    innerData.RendezvousLinkSpecifiers
                    |> Seq.filter(fun linkS ->
                        linkS.Type = LinkSpecifierType.TLSOverTCPV4
                    )
                    |> Seq.tryExactlyOne

                match linkSpecifierOpt with
                | Some linkSpecifier -> linkSpecifier.ToEndPoint()
                | None -> failwith "No rendezvous endpoint found!"

            let rendezvousFingerPrint =
                let linkSpecifierOpt =
                    innerData.RendezvousLinkSpecifiers
                    |> Seq.filter(fun linkS ->
                        linkS.Type = LinkSpecifierType.LegacyIdentity
                    )
                    |> Seq.tryExactlyOne

                match linkSpecifierOpt with
                | Some linkSpecifier -> linkSpecifier.Data
                | None -> failwith "No rendezvous fingerprint found!"

            let connectToRendezvousJob =
                tryConnectingToRendezvous
                    rendezvousEndpoint
                    rendezvousFingerPrint
                    innerData.OnionKey
                    innerData.RendezvousCookie
                    introduce.ClientPublicKey
                    introAuthPubKey
                    introEncPrivKey
                    introEncPubKey

            do!
                FSharpUtil.Retry<SocketException, NOnionException>
                    connectToRendezvousJob
                    maxRendezvousConnectRetryCount

            return ()
        }

    member self.StartAsync() =
        self.Start() |> Async.StartAsTask

    member self.RegisterIntroductionPoints() =
        async {
            let rec createIntroductionPoint() =
                async {
                    try
                        let! guardEndPoint, guardNodeDetail =
                            directory.GetRouter RouterType.Guard

                        let! _, introNodeDetail =
                            directory.GetRouter RouterType.Normal

                        match introNodeDetail with
                        | FastCreate ->
                            return
                                failwith
                                    "Unreachable, directory always returns non-fast connection info"
                        | Create(address, onionKey, fingerprint) ->
                            let! guard = TorGuard.NewClient guardEndPoint
                            let circuit = TorCircuit guard

                            let encKeyPair, authKeyPair =
                                let kpGen = Ed25519KeyPairGenerator()
                                let kpGenX = X25519KeyPairGenerator()

                                let random = SecureRandom()

                                kpGen.Init(
                                    Ed25519KeyGenerationParameters random
                                )

                                kpGenX.Init(
                                    X25519KeyGenerationParameters random
                                )

                                kpGenX.GenerateKeyPair(),
                                kpGen.GenerateKeyPair()

                            let introductionPointInfo =
                                {
                                    IntroductionPointInfo.Address = address
                                    AuthKey = authKeyPair
                                    EncryptionKey = encKeyPair
                                    OnionKey = onionKey
                                    Fingerprint = fingerprint
                                    MasterPublicKey =
                                        masterPublicKey.GetEncoded()
                                }

                            do! circuit.Create guardNodeDetail |> Async.Ignore
                            do! circuit.Extend introNodeDetail |> Async.Ignore

                            do!
                                circuit.RegisterAsIntroductionPoint
                                    (Some authKeyPair)
                                    self.RelayIntroduceCallback

                            let safeRegister() =
                                let introductionPointAlreadyExists =
                                    introductionPointKeys
                                    |> Map.toSeq
                                    |> Seq.exists(fun (_authKey, info) ->
                                        info.Address = introductionPointInfo.Address
                                    )

                                if introductionPointAlreadyExists then
                                    failwith
                                        "duplicate introduction point, try again!"
                                else
                                    guardNode <- guard :: guardNode

                                    introductionPointKeys <-
                                        Map.add
                                            ((authKeyPair.Public
                                             :?> Ed25519PublicKeyParameters)
                                                 .GetEncoded()
                                             |> Convert.ToBase64String)
                                            introductionPointInfo
                                            introductionPointKeys

                            introductionPointSemaphore.RunSyncWithSemaphore
                                safeRegister
                    with
                    | ex ->
                        TorLogger.Log(
                            sprintf
                                "TorServiceHost: failed to register introduction point, ex=%s"
                                (ex.ToString())
                        )

                        return! createIntroductionPoint()

                }

            do!
                Seq.replicate
                    Constants.IntroductionPointCount
                    (createIntroductionPoint())
                |> Async.Parallel
                |> Async.Ignore
        }

    member self.UploadDescriptor
        (directoryToUploadTo: string)
        (document: HiddenServiceFirstLayerDescriptorDocument)
        (retry: int)
        =
        async {
            if retry > maxDescriptorUploadRetryCount then
                return ()
            else
                try
                    let hsDirectoryNode =
                        directory.GetCircuitNodeDetailByIdentity
                            directoryToUploadTo

                    let descriptor =
                        directory.GetDescriptorByIdentity directoryToUploadTo

                    if descriptor.Hibernating
                       || descriptor.NTorOnionKey.IsNone
                       || descriptor.Fingerprint.IsNone then
                        return ()
                    else
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

                        let! _response =
                            TorHttpClient(
                                dirStream,
                                Constants.DefaultHttpHost
                            )
                                .PostString
                                (sprintf
                                    "/tor/hs/%i/publish"
                                    Constants.HiddenServiceVersion)
                                (document.ToString())

                        return ()
                with
                | ex ->
                    TorLogger.Log(
                        sprintf
                            "TorServiceHost: hs descriptor upload failed, ex=%s"
                            (ex.ToString())
                    )

                    return!
                        self.UploadDescriptor
                            directoryToUploadTo
                            document
                            (retry + 1)
        }

    member self.BuildAndUploadDescriptor
        periodNum
        periodLength
        srv
        (networkStatus: NetworkStatusDocument)
        =
        async {
            let blindedPublicKey =
                HiddenServicesCipher.BuildBlindedPublicKey
                    (periodNum, periodLength)
                    (masterPublicKey.GetEncoded())

            let! responsibleDirs =
                directory.GetResponsibleHiddenServiceDirectories
                    blindedPublicKey
                    srv
                    periodNum
                    periodLength
                    Constants.HsDirSpreadStore

            let revisionCounter =
                //PRIVACY: this should be encrypted with an OPE cipher
                //to mask server's time skew
                let currentSrvStartTime =
                    HSUtility.GetStartTimeOfCurrentSRVProtocolRun
                        DateTime.UtcNow
                        (networkStatus.GetVotingInterval())

                (DateTime.UtcNow - currentSrvStartTime)
                    .TotalSeconds
                |> int64
                |> Some

            let getEncryptionKeys(input: array<byte>) =
                let keyBytes =
                    input
                    |> HiddenServicesCipher.CalculateShake256(
                        Constants.KeyS256Length
                        + Constants.IVS256Length
                        + Constants.HSDirEncryption.MacKeyLength
                    )

                keyBytes |> Array.take Constants.KeyS256Length,
                keyBytes
                |> Array.skip Constants.KeyS256Length
                |> Array.take Constants.IVS256Length,
                keyBytes
                |> Array.skip(Constants.KeyS256Length + Constants.IVS256Length)
                |> Array.take Constants.HSDirEncryption.MacKeyLength

            let secretInput =
                Array.concat
                    [
                        blindedPublicKey
                        HiddenServicesCipher.GetSubCredential
                            (periodNum, periodLength)
                            (masterPublicKey.GetEncoded())
                        revisionCounter.Value
                        |> uint64
                        |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                    ]

            let outerWrapper =
                let encryptedSecondLayer =
                    let encryptedFirstLayer =
                        let innerCoreInBytes =
                            let createIntoductionPointEntry
                                (info: IntroductionPointInfo)
                                =
                                let linkSpecifiersInBytes =
                                    let linkSpecifiers =
                                        [
                                            LinkSpecifier.CreateFromEndPoint
                                                info.Address
                                            {
                                                LinkSpecifier.Type =
                                                    LinkSpecifierType.LegacyIdentity
                                                Data = info.Fingerprint
                                            }
                                        ]

                                    Array.concat
                                        [
                                            linkSpecifiers.Length
                                            |> byte
                                            |> Array.singleton
                                            linkSpecifiers
                                            |> List.map(fun link ->
                                                link.ToBytes()
                                            )
                                            |> Array.concat
                                        ]

                                let authKeyCert =
                                    Certificate.CreateNew
                                        CertType.IntroPointAuthKeySignedByDescriptorSigningKey
                                        ((info.AuthKey.Public
                                        :?> Ed25519PublicKeyParameters)
                                            .GetEncoded())
                                        (descriptorSigningPublicKey.GetEncoded())
                                        (descriptorSigningPrivateKey.GetEncoded
                                            ())
                                        Constants.HiddenServiceDescriptorCertificateLifetime

                                let encKeyBytes =
                                    (info.EncryptionKey.Public
                                    :?> X25519PublicKeyParameters)
                                        .GetEncoded()

                                let encKeyCert =
                                    let convertedX25519Key =
                                        match
                                            Ed25519.Ed25519PublicKeyFromCurve25519
                                                (
                                                    encKeyBytes,
                                                    false
                                                )
                                            with
                                        | true, output -> output
                                        | false, _ ->
                                            failwith
                                                "Should not happen, Ed25519PublicKeyFromCurve25519 will never return false"

                                    Certificate.CreateNew
                                        CertType.IntroPointEncKeySignedByDescriptorSigningKey
                                        convertedX25519Key
                                        (descriptorSigningPublicKey.GetEncoded())
                                        (descriptorSigningPrivateKey.GetEncoded
                                            ())
                                        Constants.HiddenServiceDescriptorCertificateLifetime

                                {
                                    IntroductionPointEntry.OnionKey =
                                        Some info.OnionKey
                                    AuthKey = Some authKeyCert
                                    EncKey = Some encKeyBytes
                                    EncKeyCert = Some encKeyCert
                                    LinkSpecifiers =
                                        linkSpecifiersInBytes |> Some
                                }

                            { HiddenServiceDescriptorDocument.Default with
                                IsSingleOnionService = false
                                IntroductionPoints =
                                    introductionPointKeys
                                    |> Map.values
                                    |> Seq.map createIntoductionPointEntry
                                    |> Seq.toList
                            }
                                .ToString()
                            |> Encoding.ASCII.GetBytes

                        let firstLayerSalt =
                            let salt =
                                Array.zeroCreate
                                    Constants.HSDirEncryption.SaltLength

                            RandomNumberGenerator.Create().GetBytes salt
                            salt

                        let firstLayerKey, firstLayerIV, firstLayerMacKey =
                            Array.concat
                                [
                                    secretInput
                                    firstLayerSalt
                                    Constants.HSDirEncryption.Encrypted
                                    |> Encoding.ASCII.GetBytes
                                ]
                            |> getEncryptionKeys

                        let firstLayerEncryptedData =
                            TorStreamCipher(firstLayerKey, Some firstLayerIV)
                                .Encrypt innerCoreInBytes

                        let computedFirstLayerMac =
                            HiddenServicesCipher.CalculateDirectoryEncryptionMac
                                firstLayerMacKey
                                firstLayerSalt
                                firstLayerEncryptedData

                        Array.concat
                            [
                                firstLayerSalt
                                firstLayerEncryptedData
                                computedFirstLayerMac
                            ]

                    let secondLayerPlainText =
                        {
                            HiddenServiceSecondLayerDescriptorDocument.EncryptedPayload =
                                Some encryptedFirstLayer
                        }
                            .ToString()
                        |> Encoding.ASCII.GetBytes

                    let paddedSecondLayerPlainText =
                        let paddedLength =
                            // Before encryption the plaintext is padded with NUL bytes to the nearest multiple of 10k bytes.
                            let pad = 10000
                            (secondLayerPlainText.Length + pad - 1) / pad * pad

                        Array.zeroCreate paddedLength

                    Array.Copy(
                        secondLayerPlainText,
                        paddedSecondLayerPlainText,
                        secondLayerPlainText.Length
                    )

                    let secondLayerSalt =
                        let salt =
                            Array.zeroCreate
                                Constants.HSDirEncryption.SaltLength

                        RandomNumberGenerator.Create().GetBytes salt
                        salt

                    let secondLayerKey, secondLayerIV, secondLayerMacKey =
                        Array.concat
                            [
                                secretInput
                                secondLayerSalt
                                Constants.HSDirEncryption.SuperEncrypted
                                |> Encoding.ASCII.GetBytes
                            ]
                        |> getEncryptionKeys

                    let secondLayerEncryptedData =
                        TorStreamCipher(secondLayerKey, Some secondLayerIV)
                            .Encrypt paddedSecondLayerPlainText

                    let computedSecondLayerMac =
                        HiddenServicesCipher.CalculateDirectoryEncryptionMac
                            secondLayerMacKey
                            secondLayerSalt
                            secondLayerEncryptedData

                    Array.concat
                        [
                            secondLayerSalt
                            secondLayerEncryptedData
                            computedSecondLayerMac
                        ]

                let descriptorSigningKeyCert =
                    let blindedPrivateKey =
                        HiddenServicesCipher.BuildExpandedBlindedPrivateKey
                            (periodNum, periodLength)
                            (masterPublicKey.GetEncoded())
                            (masterPrivateKey.GetEncoded())

                    Certificate.CreateNew
                        CertType.ShortTermDescriptorSigningKeyByBlindedPublicKey
                        (descriptorSigningPublicKey.GetEncoded())
                        blindedPublicKey
                        blindedPrivateKey
                        Constants.HiddenServiceDescriptorCertificateLifetime

                HiddenServiceFirstLayerDescriptorDocument.CreateNew
                    Constants.HiddenServiceVersion
                    Constants.HiddenServiceDescriptorLifetime
                    descriptorSigningKeyCert
                    revisionCounter
                    encryptedSecondLayer
                    descriptorSigningPrivateKey

            let jobs =
                responsibleDirs
                |> Seq.map(fun dir -> self.UploadDescriptor dir outerWrapper 1)

            do!
                Async.Parallel(
                    jobs,
                    maxDegreeOfParallelism = Constants.HsDirSpreadStore
                )
                |> Async.Ignore
        }

    member self.UpdateSecondDescriptor(networkStatus: NetworkStatusDocument) =
        let srv = networkStatus.SharedRandomCurrentValue.Value

        let periodNum, periodLength =
            let periodNum, periodLength = networkStatus.GetTimePeriod()

            if
                HSUtility.InPeriodBetweenTPAndSRV
                    (networkStatus.GetValidAfter())
                    (networkStatus.GetVotingInterval())
                    (networkStatus.GetHiddenServicesDirectoryInterval()) then
                periodNum, periodLength
            else
                periodNum + 1UL, periodLength

        self.BuildAndUploadDescriptor periodNum periodLength srv networkStatus

    member self.UpdateFirstDescriptor(networkStatus: NetworkStatusDocument) =
        let srv = networkStatus.SharedRandomPreviousValue.Value

        let periodNum, periodLength =
            let periodNum, periodLength = networkStatus.GetTimePeriod()

            if
                HSUtility.InPeriodBetweenTPAndSRV
                    (networkStatus.GetValidAfter())
                    (networkStatus.GetVotingInterval())
                    (networkStatus.GetHiddenServicesDirectoryInterval()) then
                periodNum - 1UL, periodLength
            else
                periodNum, periodLength

        self.BuildAndUploadDescriptor periodNum periodLength srv networkStatus

    //TODO: this should refresh every 60-120min
    member self.KeepDescriptorsUpToDate() =
        async {
            let! networkStatus = directory.GetLiveNetworkStatus()

            do! self.UpdateFirstDescriptor networkStatus
            do! self.UpdateSecondDescriptor networkStatus
        }

    member self.Start() =
        async {
            do! self.RegisterIntroductionPoints()

            do! self.KeepDescriptorsUpToDate()
        }

    member __.AcceptClient() =
        async {
            let! cancelToken = Async.CancellationToken
            cancelToken.ThrowIfCancellationRequested()

            let tryGetConnectionRequest() =
                let nextItemOpt = pendingConnectionQueue.TryUncons

                match nextItemOpt with
                | Some(nextItem, rest) ->
                    pendingConnectionQueue <- rest
                    Some nextItem
                | None -> None

            let rec getConnectionRequest() =
                async {
                    do!
                        newClientSemaphore.WaitAsync(cancelToken)
                        |> Async.AwaitTask

                    let nextItemOpt =
                        queueLock.RunSyncWithSemaphore tryGetConnectionRequest

                    match nextItemOpt with
                    | Some nextItem -> return nextItem
                    | None -> return failwith "should not happen"
                }

            let! (streamId, senderCircuit) = getConnectionRequest()
            let! stream = TorStream.Accept streamId senderCircuit
            return stream
        }

    member self.AcceptClientAsync() =
        self.AcceptClient() |> Async.StartAsTask

    member self.AcceptClientAsync(cancellationToken: CancellationToken) =
        Async.StartAsTask(
            self.AcceptClient(),
            cancellationToken = cancellationToken
        )

    member self.ExportUrl() =
        let publicKey = masterPublicKey.GetEncoded()

        let checksum =
            Array.concat
                [
                    Constants.OnionChecksumPrefix
                    |> System.Text.Encoding.ASCII.GetBytes
                    publicKey
                    Constants.HiddenServiceVersion |> byte |> Array.singleton
                ]
            |> HiddenServicesCipher.SHA3256
            |> Seq.take Constants.OnionUrlChecksumLength
            |> Seq.toArray

        (Array.concat
            [
                publicKey
                checksum
                Constants.HiddenServiceVersion |> byte |> Array.singleton
            ]
         |> Base32Util.EncodeBase32)
            .ToLower()
        + ".onion"

    member self.ExportPrivateKey() =
        masterPrivateKey
