namespace NOnion.Network

open System
open System.IO
open System.Net
open System.Threading
open System.Text.Json
open FSharpx.Collections

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

open NOnion
open NOnion.Cells.Relay
open NOnion.Crypto
open NOnion.Directory
open NOnion.Utility

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

type TorServiceHost (directory: TorDirectory) =

    let mutable introductionPointKeys: Map<string, IntroductionPointInfo> =
        Map.empty

    let mutable guardNode: Option<TorGuard> = None
    let introductionPointSemaphore: SemaphoreLocker = SemaphoreLocker ()
    let newClientSemaphore = new SemaphoreSlim (0)

    let mutable pendingConnectionQueue: Queue<uint16 * TorCircuit> = Queue.empty
    let queueLock: SemaphoreLocker = SemaphoreLocker ()

    member private self.IncomingServiceStreamCallback
        (streamId: uint16)
        (senderCircuit: TorCircuit)
        =
        async {
            let registerConnectionRequest () =
                pendingConnectionQueue <-
                    pendingConnectionQueue.Conj (streamId, senderCircuit)

                newClientSemaphore.Release () |> ignore<int>

            queueLock.RunSyncWithSemaphore registerConnectionRequest
        }

    member private self.RelayIntroduceCallback (introduce: RelayIntroduce) =
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
                | _ -> failwith "Unknown introduction point"

            let introAuthPubKey =
                introductionPointDetails.AuthKey.Public
                :?> Ed25519PublicKeyParameters

            let introEncPubKey =
                introductionPointDetails.EncryptionKey.Public
                :?> X25519PublicKeyParameters

            let introEncPrivKey =
                introductionPointDetails.EncryptionKey.Private
                :?> X25519PrivateKeyParameters

            let! networkStatus = directory.GetLiveNetworkStatus ()
            let periodInfo = networkStatus.GetTimePeriod ()

            let decryptedData, digest =
                HiddenServicesCipher.DecryptIntroductionData
                    introduce.EncryptedData
                    (X25519PublicKeyParameters (introduce.ClientPublicKey, 0))
                    (introductionPointDetails.AuthKey.Public
                    :?> Ed25519PublicKeyParameters)
                    (introductionPointDetails.EncryptionKey.Private
                    :?> X25519PrivateKeyParameters)
                    (introductionPointDetails.EncryptionKey.Public
                    :?> X25519PublicKeyParameters)
                    periodInfo
                    introductionPointDetails.MasterPublicKey

            use decryptedStream = new MemoryStream (decryptedData)
            use decryptedReader = new BinaryReader (decryptedStream)
            let innerData = RelayIntroduceInnerData.Deserialize decryptedReader

            if digest <> introduce.Mac then
                failwith "Invalid mac"

            let! endPoint, randomNodeDetails = directory.GetRouter false

            let rendEndpoint =
                (innerData.RendezvousLinkSpecifiers
                 |> Seq.filter (fun linkS ->
                     linkS.Type = LinkSpecifierType.TLSOverTCPV4
                 )
                 |> Seq.exactlyOne)
                    .ToEndPoint ()

            let rendFingerPrint =
                (innerData.RendezvousLinkSpecifiers
                 |> Seq.filter (fun linkS ->
                     linkS.Type = LinkSpecifierType.LegacyIdentity
                 )
                 |> Seq.exactlyOne)
                    .Data

            let! guard = TorGuard.NewClient endPoint

            let rendCircuit =
                TorCircuit (guard, self.IncomingServiceStreamCallback)

            do! rendCircuit.Create randomNodeDetails |> Async.Ignore

            do!
                rendCircuit.Extend (
                    CircuitNodeDetail.Create (
                        rendEndpoint,
                        innerData.OnionKey,
                        rendFingerPrint
                    )
                )
                |> Async.Ignore

            do!
                rendCircuit.Rendezvous
                    innerData.RendezvousCookie
                    (X25519PublicKeyParameters (introduce.ClientPublicKey, 0))
                    introAuthPubKey
                    introEncPrivKey
                    introEncPubKey

            return ()
        }

    member self.StartAsync () =
        self.Start () |> Async.StartAsTask

    member self.Start () =
        let safeCreateIntroductionPoint () =
            async {
                let! _, introNodeDetail = directory.GetRouter false

                match introNodeDetail with
                | FastCreate -> return failwith "should not happen"
                | Create (address, onionKey, fingerprint) ->

                    let! guard = TorGuard.NewClient address
                    let circuit = TorCircuit guard

                    let encKeyPair, authKeyPair, randomMasterPubKey =
                        let kpGen = Ed25519KeyPairGenerator ()
                        let kpGenX = X25519KeyPairGenerator ()

                        let random = SecureRandom ()

                        kpGen.Init (Ed25519KeyGenerationParameters random)
                        kpGenX.Init (X25519KeyGenerationParameters random)

                        kpGenX.GenerateKeyPair (),
                        kpGen.GenerateKeyPair (),
                        (kpGen.GenerateKeyPair().Public
                        :?> Ed25519PublicKeyParameters)
                            .GetEncoded ()

                    let introductionPointInfo =
                        {
                            IntroductionPointInfo.Address = address
                            AuthKey = authKeyPair
                            EncryptionKey = encKeyPair
                            OnionKey = onionKey |> Convert.ToBase64String
                            Fingerprint = fingerprint |> Convert.ToBase64String
                            MasterPublicKey = randomMasterPubKey
                        }

                    guardNode <- Some guard

                    introductionPointKeys <-
                        Map.add
                            ((authKeyPair.Public :?> Ed25519PublicKeyParameters)
                                .GetEncoded ()
                             |> Convert.ToBase64String)
                            introductionPointInfo
                            introductionPointKeys

                    do! circuit.Create introNodeDetail |> Async.Ignore

                    do!
                        circuit.RegisterAsIntroductionPoint
                            (Some authKeyPair)
                            self.RelayIntroduceCallback
            }

        introductionPointSemaphore.RunAsyncWithSemaphore
            safeCreateIntroductionPoint

    member __.AcceptClient () =
        async {
            let! cancelToken = Async.CancellationToken
            cancelToken.ThrowIfCancellationRequested ()

            let tryGetConnectionRequest () =
                let nextItemOpt = pendingConnectionQueue.TryUncons

                match nextItemOpt with
                | Some (nextItem, rest) ->
                    pendingConnectionQueue <- rest
                    Some nextItem
                | None -> None

            let rec getConnectionRequest () =
                async {
                    do!
                        newClientSemaphore.WaitAsync (cancelToken)
                        |> Async.AwaitTask

                    let nextItemOpt =
                        queueLock.RunSyncWithSemaphore tryGetConnectionRequest

                    match nextItemOpt with
                    | Some nextItem -> return nextItem
                    | None -> return failwith "should not happen"
                }

            let! (streamId, senderCircuit) = getConnectionRequest ()
            let! stream = TorStream.Accept streamId senderCircuit
            return stream
        }

    member self.AcceptClientAsync () =
        self.AcceptClient () |> Async.StartAsTask

    member self.AcceptClientAsync (cancellationToken: CancellationToken) =
        Async.StartAsTask (
            self.AcceptClient (),
            cancellationToken = cancellationToken
        )

    member self.Export () =
        let exportIntroductionPoint (_key, info: IntroductionPointInfo) =
            {
                IntroductionPointPublicInfo.Address =
                    info.Address.Address.ToString ()
                Port = info.Address.Port
                OnionKey = info.OnionKey
                Fingerprint = info.Fingerprint
                AuthKey =
                    (info.AuthKey.Public :?> Ed25519PublicKeyParameters)
                        .GetEncoded ()
                    |> Convert.ToBase64String
                EncryptionKey =
                    (info.EncryptionKey.Public :?> X25519PublicKeyParameters)
                        .GetEncoded ()
                    |> Convert.ToBase64String
                MasterPublicKey = info.MasterPublicKey |> Convert.ToBase64String
            }

        introductionPointKeys
        |> Map.toList
        |> List.map exportIntroductionPoint
        |> JsonSerializer.Serialize
