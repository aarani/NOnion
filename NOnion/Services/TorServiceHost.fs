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
    }

type IntroductionPointPublicInfo =
    {
        Address: IPEndPoint
        EncryptionKey: Ed25519PublicKeyParameters
        AuthKey: Ed25519PublicKeyParameters
    }


type TorServiceHost () =

    let mutable introductionPointKeys: Map<string, IntroductionPointInfo> =
        Map.empty

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

    member self.CreateIntroductionPoint (introNodeDetail: CircuitNodeDetail) =
        let safeCreateIntroductionPoint () =
            async {
                match introNodeDetail with
                | FastCreate -> return failwith "//FIXME"
                | Create (address, _, _) ->

                    use! guard = TorGuard.NewClient address
                    let circuit = TorCircuit (guard)

                    let encKeyPair, authKeyPair =
                        let kpGen = Ed25519KeyPairGenerator ()
                        let random = SecureRandom ()

                        kpGen.Init (Ed25519KeyGenerationParameters random)

                        kpGen.GenerateKeyPair (), kpGen.GenerateKeyPair ()

                    let introductionPointInfo =
                        {
                            IntroductionPointInfo.Address = address
                            AuthKey = authKeyPair
                            EncryptionKey = encKeyPair
                        }

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
                    info.EncryptionKey.Public :?> Ed25519PublicKeyParameters
            }

        introductionPointKeys |> Map.map exportIntroductionPoint
//TODO: JSON export
