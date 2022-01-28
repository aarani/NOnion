namespace NOnion.Core.Network

open System
open System.IO
open System.Net
open System.Net.Security
open System.Net.Sockets
open System.Security.Authentication
open System.Security.Cryptography
open System.Threading

open NOnion.Core
open NOnion.Core.Cells
open NOnion.Core.Utility

type TorGuard private (client: TcpClient, sslStream: SslStream) =
    let shutdownToken = new CancellationTokenSource()

    let mutable circuitsMap: Map<uint16, ITorCircuit> = Map.empty
    // Prevents two circuit setup happening at once (to prevent race condition on writing to CircuitIds list)
    let circuitSetupLock: obj = obj()

    let sendLock = SemaphoreLocker()

    static member NewClient(ipEndpoint: IPEndPoint) =
        async {
            let tcpClient = new TcpClient()

            try
                ipEndpoint.ToString()
                |> sprintf "TorGuard: trying to connect to %s guard node"
                |> TorLogger.Log

                do!
                    tcpClient.ConnectAsync(ipEndpoint.Address, ipEndpoint.Port)
                    |> Async.AwaitTask

            with
            | exn ->
                let socketExOpt = FSharpUtil.FindException<SocketException> exn

                match socketExOpt with
                | None -> return raise <| FSharpUtil.ReRaise exn
                | Some socketEx ->
                    return raise <| GuardConnectionFailedException socketEx

            let sslStream =
                new SslStream(
                    tcpClient.GetStream(),
                    false,
                    fun _ _ _ _ -> true
                )

            ipEndpoint.ToString()
            |> sprintf "TorGuard: creating ssl connection to %s guard node"
            |> TorLogger.Log

            do!
                sslStream.AuthenticateAsClientAsync(
                    String.Empty,
                    null,
                    SslProtocols.Tls12,
                    false
                )
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.CircuitOperationTimeout

            ipEndpoint.ToString()
            |> sprintf "TorGuard: ssl connection to %s guard node authenticated"
            |> TorLogger.Log

            let guard = new TorGuard(tcpClient, sslStream)
            do! guard.Handshake()

            ipEndpoint.ToString()
            |> sprintf "TorGuard: connection with %s established"
            |> TorLogger.Log

            guard.StartListening()

            return guard
        }

    static member NewClientAsync ipEndpoint =
        TorGuard.NewClient ipEndpoint |> Async.StartAsTask

    member __.Send (circuidId: uint16) (cellToSend: ICell) =
        let safeSend() =
            async {
                use memStream = new MemoryStream(Constants.FixedPayloadLength)
                use writer = new BinaryWriter(memStream)
                cellToSend.Serialize writer

                // Write circuitId and command for the cell
                // (We assume every cell that is being sent here uses 0 as circuitId
                // because we haven't completed the handshake yet to have a circuit
                // up.)

                do!
                    circuidId
                    |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                    |> StreamUtil.Write sslStream

                do!
                    Array.singleton cellToSend.Command
                    |> StreamUtil.Write sslStream

                if Command.IsVariableLength cellToSend.Command then
                    do!
                        memStream.Length
                        |> uint16
                        |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                        |> StreamUtil.Write sslStream
                else
                    Array.zeroCreate<byte>(
                        Constants.FixedPayloadLength - int memStream.Position
                    )
                    |> writer.Write

                do! memStream.ToArray() |> StreamUtil.Write sslStream
            }

        sendLock.RunAsyncWithSemaphore safeSend

    member self.SendAsync (circuidId: uint16) (cellToSend: ICell) =
        self.Send circuidId cellToSend |> Async.StartAsTask

    member private __.ReceiveInternal() =
        async {
            (*
                If at any time "ReadFixedSize" returns None, it means that either stream is closed/disposed or
                cancellation is requested, anyhow we don't need to continue listening for new data
            *)
            let! maybeHeader =
                StreamUtil.ReadFixedSize sslStream Constants.PacketHeaderLength

            match maybeHeader with
            | Some header ->
                let circuitId =
                    header
                    |> Array.take Constants.CircuitIdLength
                    |> IntegerSerialization.FromBigEndianByteArrayToUInt16

                // Command is only one byte in size
                let commandOpt =
                    header
                    |> Array.skip Constants.CommandOffset
                    |> Array.tryHead

                match commandOpt with
                | None -> return failwith "Incomplete message header"
                | Some command ->
                    let! maybeBodyLength =
                        async {
                            if Command.IsVariableLength command then
                                let! maybeLengthBytes =
                                    StreamUtil.ReadFixedSize
                                        sslStream
                                        Constants.VariableLengthBodyPrefixLength

                                match maybeLengthBytes with
                                | Some lengthBytes ->
                                    return
                                        lengthBytes
                                        |> IntegerSerialization.FromBigEndianByteArrayToUInt16
                                        |> int
                                        |> Some
                                | None -> return None
                            else
                                return Constants.FixedPayloadLength |> Some
                        }

                    match maybeBodyLength with
                    | Some bodyLength ->
                        let! maybeBody =
                            StreamUtil.ReadFixedSize sslStream bodyLength

                        match maybeBody with
                        | Some body -> return Some(circuitId, command, body)
                        | None -> return None
                    | None -> return None
            | None -> return None
        }

    member private self.ReceiveExpected<'T when 'T :> ICell>() : Async<'T> =
        async {
            let expectedCommandType = Command.GetCommandByCellType<'T>()

            //This is only used for handshake process so circuitId doesn't matter
            let! maybeMessage = self.ReceiveInternal()

            match maybeMessage with
            | None ->
                return
                    failwith
                        "Socket got closed before receiving an expected cell"
            | Some(_circuitId, command, body) ->
                //FIXME: maybe continue instead of failing?
                if command <> expectedCommandType then
                    failwith(sprintf "Unexpected msg type %i" command)

                use memStream = new MemoryStream(body)
                use reader = new BinaryReader(memStream)
                return Command.DeserializeCell reader expectedCommandType :?> 'T
        }

    member private self.ReceiveMessage() =
        async {
            let! maybeMessage = self.ReceiveInternal()

            match maybeMessage with
            | Some(circuitId, command, body) ->
                use memStream = new MemoryStream(body)
                use reader = new BinaryReader(memStream)

                return
                    (circuitId, Command.DeserializeCell reader command) |> Some
            | None -> return None
        }

    member private self.StartListening() =
        let rec readFromStream() =
            async {
                let! maybeCell = self.ReceiveMessage()

                match maybeCell with
                | None ->
                    TorLogger.Log "TorGuard: guard receiving thread stopped"
                | Some(cid, cell) ->
                    if cid = 0us then
                        //TODO: handle control message?
                        ()
                    else
                        match circuitsMap.TryFind cid with
                        | Some circuit ->
                            // Some circuit handlers send data, which by itself might try to use the stream
                            // after it's already disposed, so we need to be able to handle cancellation during cell handling as well
                            try
                                do! circuit.HandleIncomingCell cell
                            with
                            | ex ->
                                sprintf
                                    "TorGuard: exception when trying to handle incomming cell type=%i, ex=%s"
                                    cell.Command
                                    (ex.ToString())
                                |> TorLogger.Log
                        | None ->
                            failwith(sprintf "Unknown circuit, Id = %i" cid)

                    return! readFromStream()
            }

        Async.Start(readFromStream(), shutdownToken.Token)

    member private self.Handshake() =
        async {
            TorLogger.Log "TorGuard: started handshake process"

            do!
                self.Send
                    Constants.DefaultCircuitId
                    {
                        CellVersions.Versions =
                            Constants.SupportedProtocolVersion
                    }

            let! _version = self.ReceiveExpected<CellVersions>()
            let! _certs = self.ReceiveExpected<CellCerts>()
            //TODO: Client authentication isn't implemented yet!
            do! self.ReceiveExpected<CellAuthChallenge>() |> Async.Ignore
            let! netInfo = self.ReceiveExpected<CellNetInfo>()

            do!
                self.Send
                    Constants.DefaultCircuitId
                    {
                        CellNetInfo.Time =
                            DateTimeUtils.ToUnixTimestamp DateTime.UtcNow
                        OtherAddress = netInfo.MyAddresses |> Seq.head
                        MyAddresses = List.singleton netInfo.OtherAddress
                    }

            TorLogger.Log "TorGuard: finished handshake process"
        //TODO: do security checks on handshake data
        }
        |> FSharpUtil.WithTimeout Constants.CircuitOperationTimeout

    member internal __.RegisterCircuit(circuit: ITorCircuit) : uint16 =
        let rec createCircuitId(retry: int) =
            let registerId(cid: uint16) =
                if Map.containsKey cid circuitsMap then
                    false
                else
                    circuitsMap <- circuitsMap.Add(cid, circuit)
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
                createCircuitId(retry + 1)

        lock circuitSetupLock (fun () -> createCircuitId 0)

    interface IDisposable with
        member __.Dispose() =
            shutdownToken.Cancel()
            sslStream.Dispose()
            client.Close()
            client.Dispose()
