namespace NOnion.Network

open System
open System.Net

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

open NOnion.Cells.Relay
open NOnion.Utility
open Org.BouncyCastle.Crypto.Agreement
open System.Text
open Org.BouncyCastle.Crypto.Digests
open NOnion.Directory
open NOnion.Crypto

type IntroductionPointInfo =
    {
        Address: IPEndPoint
        EncryptionKey: AsymmetricCipherKeyPair
        AuthKey: AsymmetricCipherKeyPair
        NodeDetail: CircuitNodeDetail
        Circuit: TorCircuit
        Guard: TorGuard
    }

type IntroductionPointPublicInfo =
    {
        Address: IPEndPoint
        EncryptionKey: X25519PublicKeyParameters
        AuthKey: Ed25519PublicKeyParameters
        NodeDetail: CircuitNodeDetail
    }


type TorServiceHost (directory: TorDirectory, masterKey: Ed25519PublicKeyParameters) =

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

        let randomServerKey =
            let kpGenX = X25519KeyPairGenerator ()

            let random = SecureRandom ()

            kpGenX.Init (X25519KeyGenerationParameters random)

            kpGenX.GenerateKeyPair ()


        async {
            let keyAgreement = X25519Agreement ()
            keyAgreement.Init introductionPointDetails.EncryptionKey.Private
            let exp = Array.zeroCreate keyAgreement.AgreementSize
            keyAgreement.CalculateAgreement (X25519PublicKeyParameters(introduce.ClientPublicKey, 0), exp, 0)
            let ProtoId = "tor-hs-ntor-curve25519-sha3-256-1"

            let m_hsexpand =
                ProtoId + ":hs_key_expand" |> Encoding.ASCII.GetBytes

            let t_hsenc =
                ProtoId + ":hs_key_extract" |> Encoding.ASCII.GetBytes

            let digestEngine = Sha3Digest ()

            let credential =
                digestEngine.GetByteLength () |> Array.zeroCreate

            let credentialDigestInput =
                Array.concat
                    [
                        "credential" |> Encoding.ASCII.GetBytes
                        masterKey.GetEncoded ()
                    ]

            digestEngine.BlockUpdate (
                credentialDigestInput,
                0,
                credentialDigestInput.Length
            )

            digestEngine.DoFinal (credential, 0) |> ignore<int>
                
            let! networkStatus = directory.GetNetworkStatus ()

            let blindingFactor =
                HiddenServicesCipher.CalculateBlindingFactor
                    (networkStatus.GetTimePeriod ())
                    (masterKey.GetEncoded ())

            let blindedKey =
                HiddenServicesCipher.CalculateBlindedPublicKey
                    blindingFactor
                    (masterKey.GetEncoded ())

            let subcredentialDigestInput =
                Array.concat
                    [
                        "subcredential" |> Encoding.ASCII.GetBytes
                        credential
                        blindedKey
                    ]

            let subcredential =
                digestEngine.GetByteLength () |> Array.zeroCreate

            digestEngine.BlockUpdate (
                subcredentialDigestInput,
                0,
                subcredentialDigestInput.Length
            )

            digestEngine.DoFinal (subcredential, 0) |> ignore<int>

            let intro_secret_hs_input =
                Array.concat
                    [
                        exp
                        (introductionPointDetails.AuthKey.Public :?> Ed25519PublicKeyParameters).GetEncoded ()
                        introduce.ClientPublicKey
                        (introductionPointDetails.EncryptionKey.Public :?> X25519PublicKeyParameters).GetEncoded ()
                        ProtoId |> Encoding.ASCII.GetBytes
                    ]

            let infot = Array.concat [ m_hsexpand; subcredential ]

            let finalDigestInput =
                Array.concat
                    [
                        intro_secret_hs_input
                        t_hsenc
                        infot
                    ]

            let hs_keys = digestEngine.GetByteLength () |> Array.zeroCreate

            digestEngine.BlockUpdate (
                finalDigestInput,
                0,
                finalDigestInput.Length
            )

            digestEngine.DoFinal (hs_keys, 0) |> ignore<int>

            let DEC_KEY = hs_keys |> Array.take 16
            let MAC_KEY = hs_keys |> Array.skip 16 |> Array.take 16

            let aesCtr = TorStreamCipher(DEC_KEY, None)

            let decryptedData = 
                introduce.EncryptedData 
                |> aesCtr.Encrypt

            let expXy = Array.zeroCreate keyAgreement.AgreementSize
            let expXb = Array.zeroCreate keyAgreement.AgreementSize
            keyAgreement.CalculateAgreement (randomServerKey.Public :?> X25519PublicKeyParameters, expXy, 0)
            keyAgreement.CalculateAgreement (introductionPointDetails.EncryptionKey.Public :?> X25519PublicKeyParameters, expXb, 0)

            let rend_secret_hs_input = 
                Array.concat 
                    [
                        expXy
                        expXb
                        (introductionPointDetails.AuthKey.Public :?> Ed25519PublicKeyParameters).GetEncoded()
                        (introductionPointDetails.EncryptionKey.Public :?> X25519PublicKeyParameters).GetEncoded()
                        introduce.ClientPublicKey
                        (randomServerKey.Public :?> X25519PublicKeyParameters).GetEncoded()
                        ProtoId |> Encoding.ASCII.GetBytes
                    ]
            let t_hsverify =
                ProtoId + ":hs_verify" |> Encoding.ASCII.GetBytes
            let t_hsmac =
                ProtoId + ":hs_mac" |> Encoding.ASCII.GetBytes
            let NTOR_KEY_SEED = HiddenServicesCipher.CalculateMacWithSHA3256 rend_secret_hs_input t_hsenc 
            let verify = HiddenServicesCipher.CalculateMacWithSHA3256 rend_secret_hs_input t_hsverify
            let auth_input = 
                Array.concat 
                    [
                        verify
                        (introductionPointDetails.AuthKey.Public :?> Ed25519PublicKeyParameters).GetEncoded()
                        (introductionPointDetails.EncryptionKey.Public :?> X25519PublicKeyParameters).GetEncoded()
                        (randomServerKey.Public :?> X25519PublicKeyParameters).GetEncoded()
                        introduce.ClientPublicKey
                        ProtoId |> Encoding.ASCII.GetBytes
                        "Server" |>Encoding.ASCII.GetBytes
                    ]
            let _AUTH_INPUT_MAC = HiddenServicesCipher.CalculateMacWithSHA3256 auth_input t_hsmac

            //JOIN RENDEZVOUS
            ()

        }
        |> Async.Start
        
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
                            Circuit = circuit
                            Guard = guard
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
                    info.EncryptionKey.Public :?> X25519PublicKeyParameters
                NodeDetail = info.NodeDetail
            }
        //TODO: JSON export
        introductionPointKeys |> Map.map exportIntroductionPoint
