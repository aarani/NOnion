namespace NOnion.Network

open System
open System.Net

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

open NOnion.Cells.Relay
open NOnion.Utility

type IntroductionPointInfo =
    {
        Address: IPEndPoint
        EncryptionKey: AsymmetricCipherKeyPair
        AuthKey: AsymmetricCipherKeyPair
        NodeDetail: CircuitNodeDetail
    }

type IntroductionPointPublicInfo =
    {
        Address: IPEndPoint
        EncryptionKey: X25519PublicKeyParameters
        AuthKey: Ed25519PublicKeyParameters
        NodeDetail: CircuitNodeDetail
    }


type TorServiceHost () =

    let mutable introductionPointKeys: Map<string, IntroductionPointInfo> =
        Map.empty

    let mutable guardNode: Option<TorGuard> = None
    let introductionPointSemaphore: SemaphoreLocker = SemaphoreLocker ()

    member private self.RelayIntroduceCallback (introduce: RelayIntroduce) =
        let introductionPointDetails =
            match introduce.AuthKey with
            | RelayIntroAuthKey.ED25519SHA3256 bytes ->
                match
                    introductionPointKeys.TryGetValue
                        (Convert.ToBase64String bytes)
                    with
                | (false, _) -> failwith "Unknown introduction point"
                | (true, details) -> details
            | _ -> failwith "Unknown introduction point"

        //TODO: Decrypt?
        ()

    member self.CreateIntroductionPointAsync
        (introNodeDetail: CircuitNodeDetail)
        =
        self.CreateIntroductionPoint introNodeDetail |> Async.StartAsTask

    member self.CreateIntroductionPoint (introNodeDetail: CircuitNodeDetail) =
        let safeCreateIntroductionPoint () =
            async {
                match introNodeDetail with
                | FastCreate -> return failwith "//FIXME"
                | Create (address, _, _) ->

                    let! guard = TorGuard.NewClient address
                    let circuit = TorCircuit (guard)

                    let encKeyPair, authKeyPair =
                        let kpGen = Ed25519KeyPairGenerator ()
                        let kpGenX = X25519KeyPairGenerator ()

                        let random = SecureRandom ()

                        kpGen.Init (Ed25519KeyGenerationParameters random)
                        kpGenX.Init (X25519KeyGenerationParameters random)

                        kpGenX.GenerateKeyPair (), kpGen.GenerateKeyPair ()

                    let introductionPointInfo =
                        {
                            IntroductionPointInfo.Address = address
                            AuthKey = authKeyPair
                            EncryptionKey = encKeyPair
                            NodeDetail = introNodeDetail
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

    member self.Export () =
        let exportIntroductionPoint _key (info: IntroductionPointInfo) =
            {
                IntroductionPointPublicInfo.Address = info.Address
                AuthKey = info.AuthKey.Public :?> Ed25519PublicKeyParameters
                EncryptionKey =
                    info.EncryptionKey.Public :?> X25519PublicKeyParameters
                NodeDetail = info.NodeDetail
            }
        //TODO: JSON export
        introductionPointKeys |> Map.map exportIntroductionPoint
