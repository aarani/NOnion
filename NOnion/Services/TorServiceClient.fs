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

    static member ConnectAsync
        (directory: TorDirectory)
        (masterPubKey: array<byte>)
        (info: IntroductionPointPublicInfo)
        =
        TorServiceClient.Connect directory masterPubKey info
        |> Async.StartAsTask

    static member Connect
        (directory: TorDirectory)
        (masterPubKey: array<byte>)
        (info: IntroductionPointPublicInfo)
        =
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

            let privateKey, publicKey =
                let kpGen = X25519KeyPairGenerator ()
                let random = SecureRandom ()
                kpGen.Init (X25519KeyGenerationParameters random)
                let keyPair = kpGen.GenerateKeyPair ()

                keyPair.Private :?> X25519PrivateKeyParameters,
                keyPair.Public :?> X25519PublicKeyParameters

            match rendNode with
            | Create (address, onionKey, identityKey) ->
                let introduceInnerData =
                    {
                        RelayIntroduceInnerData.OnionKey = onionKey
                        RendezvousCookie = array
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

                let! networkStatus = directory.GetLiveNetworkStatus ()
                let periodInfo = networkStatus.GetTimePeriod ()

                let (data, mac) =
                    HiddenServicesCipher.EncryptIntroductionData
                        (introduceInnerData.ToBytes ())
                        privateKey
                        publicKey
                        info.AuthKey
                        info.EncryptionKey
                        periodInfo
                        masterPubKey

                let introduce1Packet =
                    {
                        RelayIntroduce.AuthKey =
                            RelayIntroAuthKey.ED25519SHA3256 (
                                info.AuthKey.GetEncoded ()
                            )
                        Extensions = List.empty
                        ClientPublicKey = publicKey.GetEncoded ()
                        Mac = mac
                        EncryptedData = data
                    }

                let! (ep, node) = directory.GetRouter false
                use! guard = TorGuard.NewClient (ep)
                let introCircuit = TorCircuit (guard)

                do! introCircuit.Create (node) |> Async.Ignore
                do! introCircuit.Extend (info.NodeDetail) |> Async.Ignore

                let rendJoin =
                    circuit.WaitingForRendezvousJoin
                        privateKey
                        publicKey
                        info.AuthKey
                        info.EncryptionKey

                let introduceJob =
                    async {
                        let! ack = introCircuit.Introduce introduce1Packet

                        if ack.Status <> RelayIntroduceStatus.Success then
                            return
                                failwith (
                                    sprintf
                                        "Unsuccessful introduction: %A"
                                        ack.Status
                                )
                    }

                do! Async.Parallel [ introduceJob; rendJoin ] |> Async.Ignore

            | _ -> failwith "wat?"

            return
                {
                    Cookie = array
                    Directory = directory
                    RendezvousGuard = guard
                    RendezvousCircuit = circuit
                    RendezvousNodeDetail = rendNode
                    PrivateKey = privateKey
                    PublicKey = publicKey
                }
        }

    interface IDisposable with
        member self.Dispose () =
            (self.RendezvousGuard :> IDisposable).Dispose ()
