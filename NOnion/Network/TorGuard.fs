namespace NOnion.Network

open System
open System.IO
open System.Net
open System.Net.Security
open System.Net.Sockets
open System.Security.Authentication
open System.Security.Cryptography
open System.Threading

open NOnion
open NOnion.Cells
open NOnion.Utility

type TorGuard private (client: TcpClient, sslStream: SslStream) =
    let shutdownToken = new CancellationTokenSource ()

    let mutable circuitsMap: Map<uint16, ITorCircuit> = Map.empty
    // Prevents two circuit setup happening at once (to prevent race condition on writing to CircuitIds list)
    let circuitSetupLock: obj = obj ()

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

    static member NewClientAsync ipEndpoint =
        TorGuard.NewClient ipEndpoint |> Async.StartAsTask

    member __.Send (circuidId: uint16) (cellToSend: ICell) =
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

            do! Array.singleton cellToSend.Command |> sslStream.AsyncWrite

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

    member self.SendAsync (circuidId: uint16) (cellToSend: ICell) =
        self.Send circuidId cellToSend |> Async.StartAsTask

    member private __.ReceiveInternal () =
        async {
            let! header = sslStream.AsyncRead Constants.PacketHeaderLength

            let circuitId =
                header
                |> Array.take Constants.CircuitIdLength
                |> IntegerSerialization.FromBigEndianByteArrayToUInt16

            // Command is only one byte in size
            let command =
                header |> Array.skip Constants.CommandOffset |> Array.exactlyOne

            let! bodyLength =
                async {
                    if Command.IsVariableLength command then
                        let! lengthBytes =
                            sslStream.AsyncRead
                                Constants.VariableLengthBodyPrefixLength

                        return
                            lengthBytes
                            |> IntegerSerialization.FromBigEndianByteArrayToUInt16
                            |> int
                    else
                        return Constants.FixedPayloadLength
                }

            let! body = sslStream.AsyncRead bodyLength

            return (circuitId, command, body)
        }

    member private self.ReceiveExpected<'T when 'T :> ICell> () : Async<'T> =
        async {
            let expectedCommandType = Command.GetCommandByCellType<'T> ()

            //This is only used for handshake process so circuitId doesn't matter
            let! _circuitId, command, body = self.ReceiveInternal ()

            //FIXME: maybe continue instead of failing?
            if command <> expectedCommandType then
                failwith (sprintf "Unexpected msg type %d" command)

            use memStream = new MemoryStream (body)
            use reader = new BinaryReader (memStream)
            return Command.DeserializeCell reader expectedCommandType :?> 'T
        }

    member private self.ReceiveMessage () =
        async {
            let! circuitId, command, body = self.ReceiveInternal ()
            use memStream = new MemoryStream (body)
            use reader = new BinaryReader (memStream)
            return (circuitId, Command.DeserializeCell reader command)
        }

    member private self.StartListening () =
        let listeningJob () =
            async {
                //TODO: Handle socket closure and AsyncRead behaviour in case of socket being closed
                while sslStream.CanRead do
                    let! cid, cell = self.ReceiveMessage ()

                    if cid = 0us then
                        //TODO: handle control message?
                        ()
                    else
                        match circuitsMap.TryFind cid with
                        | Some circuit -> do! circuit.HandleIncomingCell cell
                        | None -> failwith "Unknown circuit"
            }

        Async.Start (listeningJob (), shutdownToken.Token)

    member private self.Handshake () =
        async {
            do!
                self.Send
                    Constants.DefaultCircuitId
                    {
                        CellVersions.Versions =
                            Constants.SupportedProtocolVersion
                    }

            let! _version = self.ReceiveExpected<CellVersions> ()
            let! _certs = self.ReceiveExpected<CellCerts> ()
            //TODO: Client authentication isn't implemented yet!
            do! self.ReceiveExpected<CellAuthChallenge> () |> Async.Ignore
            let! netInfo = self.ReceiveExpected<CellNetInfo> ()

            do!
                self.Send
                    Constants.DefaultCircuitId
                    {
                        CellNetInfo.Time =
                            DateTimeUtils.ToUnixTimestamp DateTime.UtcNow
                        OtherAddress = netInfo.MyAddresses |> Seq.head
                        MyAddresses = List.singleton netInfo.OtherAddress
                    }

        //TODO: do security checks on handshake data
        }

    member internal __.RegisterCircuit (circuit: ITorCircuit) : uint16 =
        let rec createCircuitId (retry: int) =
            let registerId (cid: uint16) =
                if Map.containsKey cid circuitsMap then
                    false
                else
                    circuitsMap <- circuitsMap.Add (cid, circuit)
                    true

            if retry >= Constants.MaxCircuitIdGenerationRetry then
                failwith "can't create a circuit"

            let randomBytes = Array.zeroCreate<byte> Constants.CircuitIdLength

            RandomNumberGenerator
                .Create()
                .GetBytes randomBytes

            let cid =
                IntegerSerialization.FromBigEndianByteArrayToUInt16 randomBytes

            if registerId cid then
                cid
            else
                createCircuitId (retry + 1)

        lock circuitSetupLock (fun () -> createCircuitId 0)

    interface IDisposable with
        member __.Dispose () =
            shutdownToken.Cancel ()
            sslStream.Dispose ()
            client.Dispose ()
