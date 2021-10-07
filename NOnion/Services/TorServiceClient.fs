namespace NOnion.Network

open System
open System.Net
open System.Security.Cryptography

open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

open NOnion.Cells.Relay
open NOnion.Utility
open NOnion.Directory
open Org.BouncyCastle.Crypto.Agreement
open System.Text
open Org.BouncyCastle.Crypto.Digests
open NOnion.Crypto


type TorServiceClient =
    private
        {
            Cookie: array<byte>
            Directory: TorDirectory
            RendezvousGuard: TorGuard
            RendezvousCircuit: TorCircuit
            RendezvousNodeDetail: CircuitNodeDetail
            PrivateKey: X25519PrivateKeyParameters
            PublicKey: X25519PublicKeyParameters
        }

    static member CreateNewAsync (directory: TorDirectory) =
        TorServiceClient.CreateNew directory |> Async.StartAsTask

    static member CreateNew (directory: TorDirectory) =
        async {
            let array = Array.zeroCreate 20

            RandomNumberGenerator
                .Create()
                .GetNonZeroBytes (array)

            let! (endpoint, guardnode) = directory.GetRouter false
            let! (_, rendNode) = directory.GetRouter false

            let! guard = TorGuard.NewClient (endpoint)
            let circuit = TorCircuit (guard)

            do! circuit.Create (guardnode) |> Async.Ignore
            do! circuit.Extend (rendNode) |> Async.Ignore
            do! circuit.RegisterAsRendezvousPoint (array)

            let keyPair =
                let kpGen = X25519KeyPairGenerator ()
                let random = SecureRandom ()
                kpGen.Init (X25519KeyGenerationParameters random)
                kpGen.GenerateKeyPair ()

            return
                {
                    Cookie = array
                    Directory = directory
                    RendezvousGuard = guard
                    RendezvousCircuit = circuit
                    RendezvousNodeDetail = rendNode
                    PrivateKey = keyPair.Private :?> X25519PrivateKeyParameters
                    PublicKey = keyPair.Public :?> X25519PublicKeyParameters
                }
        }

    member self.ConnectAsync
        (masterKey: Ed25519PublicKeyParameters)
        (info: IntroductionPointPublicInfo)
        =
        self.Connect masterKey info |> Async.StartAsTask

    member self.Connect
        (masterKey: Ed25519PublicKeyParameters)
        (info: IntroductionPointPublicInfo)
        =
        async {
            match self.RendezvousNodeDetail with
            | Create (address, onionKey, identityKey) ->
                let translateIPEndpoint (endpoint: IPEndPoint) =
                    Array.concat
                        [
                            endpoint.Address.GetAddressBytes ()
                            endpoint.Port
                            |> uint16
                            |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                        ]

                let introduce1InnerData =
                    {
                        RelayIntroducePlainData.OnionKey = onionKey
                        RendezvousCookie = self.Cookie
                        Extensions = List.empty
                        RendezvousLinkSpecifiers =
                            [
                                {
                                    LinkSpecifier.Type =
                                        LinkSpecifierType.TLSOverTCPV4
                                    Data = translateIPEndpoint address
                                }
                                {
                                    LinkSpecifier.Type =
                                        LinkSpecifierType.LegacyIdentity
                                    Data = identityKey
                                }
                            ]
                    }

                let keyAgreement = X25519Agreement ()
                keyAgreement.Init self.PrivateKey
                let exp = Array.zeroCreate keyAgreement.AgreementSize
                keyAgreement.CalculateAgreement (info.EncryptionKey, exp, 0)
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

                let! networkStatus = self.Directory.GetNetworkStatus ()

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
                            info.AuthKey.GetEncoded ()
                            self.PublicKey.GetEncoded ()
                            info.EncryptionKey.GetEncoded ()
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

                let ENC_KEY = hs_keys |> Array.take 16
                let MAC_KEY = hs_keys |> Array.skip 16 |> Array.take 16

                let rec createPacket (padding: int) = 
                    let mac =
                        introduce1InnerData.ToBytes padding
                        |> HiddenServicesCipher.CalculateMacWithSHA3256 MAC_KEY

                    let cipher = TorStreamCipher (ENC_KEY, None)

                    let encryptedData =
                        introduce1InnerData.ToBytes padding |> cipher.Encrypt

                    let introduce1Packet =
                        {
                            RelayIntroduce.AuthKey =
                                RelayIntroAuthKey.ED25519SHA3256 (
                                    info.AuthKey.GetEncoded ()
                                )
                            Extensions = List.empty
                            ClientPublicKey = self.PublicKey.GetEncoded ()
                            Mac = mac
                            EncryptedData = encryptedData
                        }
                        |> RelayIntroduce1

                    introduce1Packet

                let! (ep, node) = self.Directory.GetRouter false
                let! guard = TorGuard.NewClient (ep)
                let circuit = TorCircuit (guard)

                do! circuit.Create (node) |> Async.Ignore
                do! circuit.Extend (info.NodeDetail) |> Async.Ignore
                do! circuit.SendRelayCell 0us (createPacket 0) None

            | _ -> failwith "should not happen"
        }

    interface IDisposable with
        member self.Dispose () =
            (self.RendezvousGuard :> IDisposable).Dispose ()
