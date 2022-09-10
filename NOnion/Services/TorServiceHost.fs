namespace NOnion.Services

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Threading
open FSharpx.Collections

open Chaos.NaCl
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

open NOnion
open NOnion.Cells.Relay
open NOnion.Crypto
open NOnion.Directory
open NOnion.Utility
open NOnion.Network
open Org.BouncyCastle.Crypto.Signers
open NOnion.Http
open System.Security.Cryptography
open System.Text

type IntroductionPointInfo =
    {
        Address: IPEndPoint
        EncryptionKey: AsymmetricCipherKeyPair
        AuthKey: AsymmetricCipherKeyPair
        MasterPublicKey: array<byte>
        OnionKey: string
        Fingerprint: string
    }

type IntroductionPointPublicInfo =
    {
        Address: string
        Port: int
        EncryptionKey: string
        AuthKey: string
        OnionKey: string
        Fingerprint: string
        MasterPublicKey: string
    }

type TorServiceHost
    (
        directory: TorDirectory,
        maxRendezvousConnectRetryCount: int,
        masterKeyPair: AsymmetricCipherKeyPair
    ) =

    let mutable introductionPointKeys: Map<string, IntroductionPointInfo> =
        Map.empty

    let mutable guardNode: List<TorGuard> = List.empty
    let introductionPointSemaphore: SemaphoreLocker = SemaphoreLocker()
    let newClientSemaphore = new SemaphoreSlim(0)

    let descriptorSigningKey =
        let kpGen = Ed25519KeyPairGenerator()
        let random = SecureRandom()

        kpGen.Init(Ed25519KeyGenerationParameters random)

        kpGen.GenerateKeyPair()

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
            let safeCreateIntroductionPoint() =
                async {
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

                            kpGen.Init(Ed25519KeyGenerationParameters random)
                            kpGenX.Init(X25519KeyGenerationParameters random)

                            kpGenX.GenerateKeyPair(), kpGen.GenerateKeyPair()

                        let introductionPointInfo =
                            {
                                IntroductionPointInfo.Address = address
                                AuthKey = authKeyPair
                                EncryptionKey = encKeyPair
                                OnionKey = onionKey |> Convert.ToBase64String
                                Fingerprint =
                                    fingerprint |> Convert.ToBase64String
                                MasterPublicKey =
                                    let masterPublicKey =
                                        if not(isNull masterKeyPair) then
                                            masterKeyPair.Public
                                            :?> Ed25519PublicKeyParameters
                                        else
                                            let kpGen =
                                                Ed25519KeyPairGenerator()

                                            let random = SecureRandom()

                                            kpGen.Init(
                                                Ed25519KeyGenerationParameters
                                                    random
                                            )

                                            kpGen.GenerateKeyPair().Public
                                            :?> Ed25519PublicKeyParameters

                                    masterPublicKey.GetEncoded()

                            }

                        do! circuit.Create guardNodeDetail |> Async.Ignore
                        do! circuit.Extend introNodeDetail |> Async.Ignore

                        do!
                            circuit.RegisterAsIntroductionPoint
                                (Some authKeyPair)
                                self.RelayIntroduceCallback

                        guardNode <- guard :: guardNode

                        introductionPointKeys <-
                            Map.add
                                ((authKeyPair.Public
                                 :?> Ed25519PublicKeyParameters)
                                     .GetEncoded()
                                 |> Convert.ToBase64String)
                                introductionPointInfo
                                introductionPointKeys
                }

            while introductionPointKeys.Count < 3 do
                try
                    do!
                        introductionPointSemaphore.RunAsyncWithSemaphore
                            safeCreateIntroductionPoint
                with
                | ex ->
                    // Silence exceptions in registering introduction points
                    TorLogger.Log(
                        sprintf
                            "TorServiceHost: failed to register introduction point, ex=%s"
                            (ex.ToString())
                    )
        }

    member self.UploadDescriptor
        (responsibleDirs: List<string>)
        (document: HiddenServiceFirstLayerDescriptorDocument)
        (retry: int)
        =
        async {
            match responsibleDirs with
            | [] -> ()
            | _ :: tail when retry > 2 ->
                return! self.UploadDescriptor tail document 0
            | responsibleDir :: tail ->
                try
                    let hsDirectoryNode =
                        directory.GetCircuitNodeDetailByIdentity responsibleDir

                    let descriptor =
                        directory.GetDescriptorByIdentity responsibleDir

                    if descriptor.Hibernating
                       || descriptor.NTorOnionKey.IsNone
                       || descriptor.Fingerprint.IsNone then
                        return! self.UploadDescriptor tail document 0
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
                            TorHttpClient(dirStream, "127.0.0.1").PostString
                                "/tor/hs/3/publish"
                                (document.ToString())

                        return! self.UploadDescriptor tail document 0
                with
                | _ ->
                    return!
                        self.UploadDescriptor
                            responsibleDirs
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
                    ((masterKeyPair.Public :?> Ed25519PublicKeyParameters)
                        .GetEncoded())

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

            let createIntoductionPointEntry(info: IntroductionPointInfo) =
                let linkSpecifiersInBytes =
                    let linkSpecifiers =
                        [
                            LinkSpecifier.CreateFromEndPoint info.Address
                            {
                                LinkSpecifier.Type =
                                    LinkSpecifierType.LegacyIdentity
                                Data = Convert.FromBase64String info.Fingerprint
                            }
                        ]

                    Array.concat
                        [
                            linkSpecifiers.Length |> byte |> Array.singleton

                            linkSpecifiers
                            |> List.map(fun link -> link.ToBytes())
                            |> Array.concat
                        ]

                let authKeyCert =
                    let unsignedCert =
                        {
                            Certificate.Version = 1uy
                            CertKeyType = 1uy
                            Type =
                                CertType.IntroPointAuthKeySignedByDescriptorSigningKey
                            CertifiedKey =
                                (info.AuthKey.Public
                                :?> Ed25519PublicKeyParameters)
                                    .GetEncoded()
                            //TODO(PRIVACY?): tor uses nearest hour instead of Now
                            ExpirationDate =
                                DateTime.UtcNow.AddHours(3.).Subtract(
                                    DateTime(1970, 1, 1)
                                )
                                    .TotalHours
                                |> uint
                            Extensions =
                                List.singleton(
                                    {
                                        CertificateExtension.Type =
                                            CertificateExtensionType.SignedWithEd25519Key
                                        Flags = 0uy
                                        Data =
                                            (descriptorSigningKey.Public
                                            :?> Ed25519PublicKeyParameters)
                                                .GetEncoded()
                                    }
                                )
                            Signature = Array.empty
                        }

                    let unsignedCertBytes = unsignedCert.ToBytes true

                    let signer = Ed25519Signer()
                    signer.Init(true, descriptorSigningKey.Private)

                    signer.BlockUpdate(
                        unsignedCertBytes,
                        0,
                        unsignedCertBytes.Length
                    )

                    { unsignedCert with
                        Signature = signer.GenerateSignature()
                    }

                let encKeyCert =
                    let unsignedCert =
                        {
                            Certificate.Version = 1uy
                            CertKeyType = 1uy
                            Type =
                                CertType.IntroPointEncKeySignedByDescriptorSigningKey
                            CertifiedKey =
                                let x25519 =
                                    info.EncryptionKey.Public
                                    :?> X25519PublicKeyParameters

                                match
                                    Ed25519.Ed25519PublicKeyFromCurve25519
                                        (
                                            x25519.GetEncoded(),
                                            false
                                        )
                                    with
                                | true, output -> output
                                | false, _ ->
                                    failwith
                                        "Should not happen, Ed25519PublicKeyFromCurve25519 will never return false"
                            ExpirationDate =
                                DateTime.UtcNow.AddHours(3.).Subtract(
                                    DateTime(1970, 1, 1)
                                )
                                    .TotalHours
                                |> uint
                            Extensions =
                                List.singleton(
                                    {
                                        CertificateExtension.Type =
                                            CertificateExtensionType.SignedWithEd25519Key
                                        Flags = 0uy
                                        Data =
                                            (descriptorSigningKey.Public
                                            :?> Ed25519PublicKeyParameters)
                                                .GetEncoded()
                                    }
                                )
                            Signature = Array.empty
                        }

                    let unsignedCertBytes = unsignedCert.ToBytes true

                    let signer = Ed25519Signer()
                    signer.Init(true, descriptorSigningKey.Private)

                    signer.BlockUpdate(
                        unsignedCertBytes,
                        0,
                        unsignedCertBytes.Length
                    )

                    { unsignedCert with
                        Signature = signer.GenerateSignature()
                    }

                {
                    IntroductionPointEntry.OnionKey =
                        Convert.FromBase64String info.OnionKey |> Some
                    AuthKey = authKeyCert.ToBytes false |> Some
                    EncKey =
                        (info.EncryptionKey.Public :?> X25519PublicKeyParameters)
                            .GetEncoded()
                        |> Some
                    EncKeyCert = encKeyCert.ToBytes false |> Some
                    LinkSpecifiers = linkSpecifiersInBytes |> Some
                }

            let getEncryptionKeys(input: array<byte>) =
                let keyBytes =
                    input
                    |> HiddenServicesCipher.CalculateShake256(
                        Constants.KeyS256Length + Constants.IVS256Length + 32
                    )

                keyBytes |> Array.take Constants.KeyS256Length,
                keyBytes
                |> Array.skip Constants.KeyS256Length
                |> Array.take Constants.IVS256Length,
                keyBytes
                |> Array.skip(Constants.KeyS256Length + Constants.IVS256Length)
                |> Array.take 32

            let secretInput =
                Array.concat
                    [
                        blindedPublicKey
                        HiddenServicesCipher.GetSubCredential
                            (periodNum, periodLength)
                            ((masterKeyPair.Public
                            :?> Ed25519PublicKeyParameters)
                                .GetEncoded())
                        revisionCounter.Value
                        |> uint64
                        |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                    ]


            let encryptedFirstLayer =
                let innerCoreInBytes =
                    {
                        HiddenServiceDescriptorDocument.Create2Formats =
                            Some "2"
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
                    let salt = Array.zeroCreate 16
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
                    Array.concat
                        [
                            firstLayerMacKey.Length
                            |> uint64
                            |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            firstLayerMacKey
                            firstLayerSalt.Length
                            |> uint64
                            |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            firstLayerSalt
                            firstLayerEncryptedData
                        ]
                    |> HiddenServicesCipher.SHA3256

                Array.concat
                    [
                        firstLayerSalt
                        firstLayerEncryptedData
                        computedFirstLayerMac
                    ]

            let encryptedSecondLayer =
                let secondLayerPlainText =
                    {
                        HiddenServiceSecondLayerDescriptorDocument.EncryptedPayload =
                            Some encryptedFirstLayer
                    }
                        .ToString()
                    |> Encoding.ASCII.GetBytes

                let paddedSecondLayerPlainText =
                    let paddedLength =
                        let pad = 10000
                        (secondLayerPlainText.Length + pad - 1) / pad * pad

                    Array.zeroCreate paddedLength

                Array.Copy(
                    secondLayerPlainText,
                    paddedSecondLayerPlainText,
                    secondLayerPlainText.Length
                )

                let secondLayerSalt =
                    let salt = Array.zeroCreate 16
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
                    Array.concat
                        [
                            secondLayerMacKey.Length
                            |> uint64
                            |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            secondLayerMacKey
                            secondLayerSalt.Length
                            |> uint64
                            |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            secondLayerSalt
                            secondLayerEncryptedData
                        ]
                    |> HiddenServicesCipher.SHA3256

                Array.concat
                    [
                        secondLayerSalt
                        secondLayerEncryptedData
                        computedSecondLayerMac
                    ]

            let outerWrapper =
                let descriptorSigningKeyCert =
                    let unsignedDescriptorSigningKeyCert =
                        {
                            Certificate.Version = 1uy
                            CertKeyType = 1uy
                            Type =
                                CertType.ShortTermDescriptorSigningKeyByBlindedPublicKey
                            CertifiedKey =
                                (descriptorSigningKey.Public
                                :?> Ed25519PublicKeyParameters)
                                    .GetEncoded()
                            ExpirationDate =
                                DateTime.UtcNow.AddHours(3.).Subtract(
                                    DateTime(1970, 1, 1)
                                )
                                    .TotalHours
                                |> uint
                            Extensions =
                                List.singleton(
                                    {
                                        CertificateExtension.Type =
                                            CertificateExtensionType.SignedWithEd25519Key
                                        Flags = 0uy
                                        Data = blindedPublicKey
                                    }
                                )
                            Signature = Array.empty
                        }

                    let unsignedDescriptorSigningKeyCertBytes =
                        unsignedDescriptorSigningKeyCert.ToBytes true

                    let signature = Array.zeroCreate<byte> 64

                    let blindedPrivateKey =
                        HiddenServicesCipher.BuildExpandedBlindedPrivateKey
                            (periodNum, periodLength)
                            ((masterKeyPair.Public
                            :?> Ed25519PublicKeyParameters)
                                .GetEncoded())
                            ((masterKeyPair.Private
                            :?> Ed25519PrivateKeyParameters)
                                .GetEncoded())

                    Ed25519.SignWithPrehashedPrivateKey(
                        ArraySegment signature,
                        ArraySegment unsignedDescriptorSigningKeyCertBytes,
                        ArraySegment blindedPrivateKey,
                        ArraySegment blindedPublicKey
                    )

                    { unsignedDescriptorSigningKeyCert with
                        Signature = signature
                    }

                let certInBytes = descriptorSigningKeyCert.ToBytes false

                let unsignedOuterWrapper =
                    {
                        HiddenServiceFirstLayerDescriptorDocument.EncryptedPayload =
                            Some encryptedSecondLayer
                        Version = Some 3
                        Lifetime = Some 180
                        RevisionCounter = revisionCounter
                        Signature = None
                        SigningKeyCert = Some(certInBytes)
                    }

                let unsignedOuterWrapperInBytes =
                    "Tor onion service descriptor sig v3"
                    + unsignedOuterWrapper.ToString()
                    |> System.Text.Encoding.ASCII.GetBytes

                let signer = Ed25519Signer()
                signer.Init(true, descriptorSigningKey.Private)

                signer.BlockUpdate(
                    unsignedOuterWrapperInBytes,
                    0,
                    unsignedOuterWrapperInBytes.Length
                )

                let signature = signer.GenerateSignature()

                { unsignedOuterWrapper with
                    Signature = Some signature
                }

            do! self.UploadDescriptor responsibleDirs outerWrapper 0
        }

    member self.UpdateSecondDescriptor(networkStatus: NetworkStatusDocument) =
        async {
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

            return!
                self.BuildAndUploadDescriptor
                    periodNum
                    periodLength
                    srv
                    networkStatus
        }

    member self.UpdateFirstDescriptor(networkStatus: NetworkStatusDocument) =
        async {
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

            return!
                self.BuildAndUploadDescriptor
                    periodNum
                    periodLength
                    srv
                    networkStatus
        }

    //TODO: this should refresh every 60-120min
    member self.KeepDescriptorsUpToDate() =
        async {
            let! networkStatus = directory.GetLiveNetworkStatus()

            do! self.UpdateFirstDescriptor networkStatus
            do! self.UpdateSecondDescriptor networkStatus

            ()
        }

    member self.Start() =
        async {
            do! self.RegisterIntroductionPoints()

            if not(isNull masterKeyPair) then
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

    member self.Export() : IntroductionPointPublicInfo =
        let exportIntroductionPoint(_key, info: IntroductionPointInfo) =
            {
                IntroductionPointPublicInfo.Address =
                    info.Address.Address.ToString()
                Port = info.Address.Port
                OnionKey = info.OnionKey
                Fingerprint = info.Fingerprint
                AuthKey =
                    (info.AuthKey.Public :?> Ed25519PublicKeyParameters)
                        .GetEncoded()
                    |> Convert.ToBase64String
                EncryptionKey =
                    (info.EncryptionKey.Public :?> X25519PublicKeyParameters)
                        .GetEncoded()
                    |> Convert.ToBase64String
                MasterPublicKey = info.MasterPublicKey |> Convert.ToBase64String
            }

        let maybeIntroductionPointPublicInfo =
            introductionPointKeys
            |> Map.toList
            |> List.map exportIntroductionPoint
            |> SeqUtils.TakeRandom 1
            |> Seq.tryExactlyOne

        match maybeIntroductionPointPublicInfo with
        | Some introductionPointPublicInfo -> introductionPointPublicInfo
        | None -> failwith "No introduction point found!"

    member self.ExportUrl() =
        let publicKey =
            (masterKeyPair.Public :?> Ed25519PublicKeyParameters)
                .GetEncoded()

        let checksum =
            Array.concat
                [
                    ".onion checksum" |> System.Text.Encoding.ASCII.GetBytes
                    publicKey
                    Array.singleton 3uy
                ]
            |> HiddenServicesCipher.SHA3256
            |> Seq.take 2
            |> Seq.toArray

        (Array.concat
            [
                publicKey
                checksum
                Array.singleton 3uy
            ]
         |> Base32Util.EncodeBase32)
            .ToLower()
        + ".onion"
