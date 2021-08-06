namespace NOnion

open System
open System.IO
open System.Net
open System.Net.Security
open System.Net.Sockets
open System.Security.Authentication
open System.Reactive.Subjects

open NOnion.Cells
open NOnion.Utility
open System.Threading.Tasks
open System.Threading
open System.Collections.Concurrent


type TorGuard private (client: TcpClient, sslStream: SslStream) =
    let client = client
    let sslStream = sslStream
    let messagesEvent = new Event<uint16 * ICell> ()
    let shutdownToken = new CancellationTokenSource ()

    let mutable circuitIds: list<uint16> = List.empty
    (* Prevents two circuit setup happening at once (to prevent race condition on writing to CircuitIds list) *)
    let circuitSetupLock: obj = obj ()


    [<CLIEvent>]
    member this.MessageReceived = messagesEvent.Publish

    static member NewClient (ipEndpoint: IPEndPoint) =
        async {
            let tcpClient = new TcpClient ()

            do!
                tcpClient.ConnectAsync (ipEndpoint.Address, ipEndpoint.Port)
                |> Async.AwaitTask

            let sslStream =
                new SslStream (
                    tcpClient.GetStream (),
                    false,
                    fun _ _ _ _ -> true
                )

            do!
                sslStream.AuthenticateAsClientAsync (
                    String.Empty,
                    null,
                    SslProtocols.Tls12,
                    false
                )
                |> Async.AwaitTask

            let guard = new TorGuard (tcpClient, sslStream)
            do! guard.Handshake ()
            guard.StartListening ()

            return guard
        }

    static member NewClientAsTask ipEndpoint =
        TorGuard.NewClient ipEndpoint |> Async.StartAsTask

    member self.Send (circuidId: uint16) (cellToSend: ICell) =
        async {
            use memStream = new MemoryStream (Constants.FixedPayloadLength)
            use writer = new BinaryWriter (memStream)
            cellToSend.Serialize writer

            // Write circuitId and command for the cell
            // (We assume every cell that is being sent here uses 0 as circuitId
            // because we haven't completed the handshake yet to have a circuit
            // up.)

            do!
                circuidId
                |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                |> sslStream.AsyncWrite

            do! [| cellToSend.Command |] |> sslStream.AsyncWrite

            if Command.IsVariableLength cellToSend.Command then
                do!
                    memStream.Length
                    |> uint16
                    |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                    |> sslStream.AsyncWrite
            else
                Array.zeroCreate<byte> (
                    Constants.FixedPayloadLength - int memStream.Position
                )
                |> writer.Write

            do! memStream.ToArray () |> sslStream.AsyncWrite
        }

    member self.SendAsTask (circuidId: uint16) (cellToSend: ICell) =
        self.Send circuidId cellToSend |> Async.StartAsTask

    member private self.ReceiveExcpected<'T when 'T :> ICell> () : Async<'T> =
        async {
            let expectedCommandType = Command.GetCommandByCellType<'T> ()
            let! header = sslStream.AsyncRead 3

            if header.[2] <> expectedCommandType then
                failwith
                <| sprintf
                    "Unexpected Msg, Expected: %i %i"
                    header.[2]
                    expectedCommandType

            let! bodyLength =
                async {
                    if Command.IsVariableLength expectedCommandType then
                        let! lengthBytes = sslStream.AsyncRead (2)

                        return
                            lengthBytes
                            |> IntegerSerialization.FromBigEndianByteArrayToUInt16
                            |> int
                    else
                        return Constants.FixedPayloadLength
                }

            let! body = sslStream.AsyncRead bodyLength

            use memStream = new MemoryStream (body)
            use reader = new BinaryReader (memStream)
            return Command.DeserializeCell reader expectedCommandType :?> 'T
        }

    member private self.ReceiveMessage () =
        async {
            let! header = sslStream.AsyncRead 3

            let circuitId =
                header.[0..1]
                |> IntegerSerialization.FromBigEndianByteArrayToUInt16

            let command = header.[2]

            let! bodyLength =
                async {
                    if Command.IsVariableLength command then
                        let! lengthBytes = sslStream.AsyncRead 2

                        return
                            lengthBytes
                            |> IntegerSerialization.FromBigEndianByteArrayToUInt16
                            |> int
                    else
                        return Constants.FixedPayloadLength
                }

            let! body = sslStream.AsyncRead (bodyLength)

            use memStream = new MemoryStream (body)
            use reader = new BinaryReader (memStream)
            return (circuitId, Command.DeserializeCell reader command)
        }

    member private self.StartListening () =
        let listeningJob () =
            async {
                while sslStream.CanRead do
                    let! message = self.ReceiveMessage ()
                    messagesEvent.Trigger message

            //On completed?
            }

        Async.Start (listeningJob (), shutdownToken.Token)

    member private self.Handshake () =
        async {
            do!
                self.Send
                    0us
                    {
                        CellVersions.Versions =
                            Constants.SupportedProtocolVersion
                    }

            let! version = self.ReceiveExcpected<CellVersions> ()
            let! certs = self.ReceiveExcpected<CellCerts> ()
            // Client authentication isn't implemented yet!
            do! self.ReceiveExcpected<CellAuthChallenge> () |> Async.Ignore
            let! netInfo = self.ReceiveExcpected<CellNetInfo> ()

            do!
                self.Send
                    0us
                    {
                        CellNetInfo.Time =
                            DateTimeUtils.ToUnixTimestamp DateTime.UtcNow
                        OtherAddress = netInfo.MyAddresses |> Seq.head
                        MyAddresses = [ netInfo.OtherAddress ]
                    }

        //TODO: do security checks on handshake data
        }

    member internal self.RegisterCircuitId (cid: uint16) : bool =
        let safeRegister () =
            if List.contains cid circuitIds then
                false
            else
                circuitIds <- circuitIds @ [ cid ]
                true

        lock circuitSetupLock safeRegister

    interface IDisposable with
        member self.Dispose () =
            shutdownToken.Cancel ()
            sslStream.Dispose ()
            client.Dispose ()
