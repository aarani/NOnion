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

type internal GuardSendMessage =
    {
        CircuitId: uint16
        CellToSend: ICell
        ReplyChannel: AsyncReplyChannel<OperationResult<unit>>
    }

module ExceptionUtil =
    let RunGuardJobWithExceptionHandling<'T> job : Async<'T> =
        async {
            try
                return! job
            with
            | exn ->
                match FSharpUtil.FindException<AuthenticationException> exn with
                | Some authEx ->
                    return raise <| GuardConnectionFailedException authEx
                | None ->
                    match FSharpUtil.FindException<SocketException> exn with
                    | Some socketEx ->
                        return raise <| GuardConnectionFailedException socketEx
                    | None ->
                        match FSharpUtil.FindException<IOException> exn with
                        | Some ioEx ->
                            return raise <| GuardConnectionFailedException ioEx
                        | None -> return raise <| FSharpUtil.ReRaise exn
        }

type TorGuard private (client: TcpClient, sslStream: SslStream) =
    let shutdownToken = new CancellationTokenSource()

    let mutable circuitsMap: Map<uint16, ITorCircuit> = Map.empty
    // Prevents two circuit setup happening at once (to prevent race condition on writing to CircuitIds list)
    let circuitSetupLock: obj = obj()

    let rec SendMailBoxProcessor(inbox: MailboxProcessor<GuardSendMessage>) =
        let innerSend circuitId (cellToSend: ICell) =
            async {
                use memStream = new MemoryStream(Constants.FixedPayloadLength)

                use writer = new BinaryWriter(memStream)
                cellToSend.Serialize writer

                // Write circuitId and command for the cell
                // (We assume every cell that is being sent here uses 0 as circuitId
                // because we haven't completed the handshake yet to have a circuit
                // up.)
                do!
                    circuitId
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

        async {
            let! cancellationToken = Async.CancellationToken
            cancellationToken.ThrowIfCancellationRequested()

            let! {
                     CircuitId = circuitId
                     CellToSend = cellToSend
                     ReplyChannel = replyChannel
                 } = inbox.Receive()

            do!
                innerSend circuitId cellToSend
                |> MailboxResultUtil.TryExecuteAsyncAndReplyAsResult
                    replyChannel

            return! SendMailBoxProcessor inbox
        }

    let sendMailBox =
        MailboxProcessor.Start(SendMailBoxProcessor, shutdownToken.Token)

    static member NewClient(ipEndpoint: IPEndPoint) =
        async {
            let tcpClient = new TcpClient()

            let innerConnectAsync(client: TcpClient) =
                async {
                    ipEndpoint.ToString()
                    |> sprintf "TorGuard: trying to connect to %s guard node"
                    |> TorLogger.Log

                    do!
                        client.ConnectAsync(ipEndpoint.Address, ipEndpoint.Port)
                        |> Async.AwaitTask
                        |> FSharpUtil.WithTimeout
                            Constants.GuardConnectionTimeout
                }

            do!
                ExceptionUtil.RunGuardJobWithExceptionHandling<unit>(
                    innerConnectAsync tcpClient
                )

            let sslStream =
                new SslStream(
                    tcpClient.GetStream(),
                    false,
                    fun _ _ _ _ -> true
                )

            ipEndpoint.ToString()
            |> sprintf "TorGuard: creating ssl connection to %s guard node"
            |> TorLogger.Log

            let innerAuthenticateAsClient(stream: SslStream) =
                stream.AuthenticateAsClientAsync(
                    String.Empty,
                    null,
                    SslProtocols.Tls12,
                    false
                )
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.CircuitOperationTimeout

            do!
                ExceptionUtil.RunGuardJobWithExceptionHandling<unit>(
                    innerAuthenticateAsClient sslStream
                )

            ipEndpoint.ToString()
            |> sprintf "TorGuard: ssl connection to %s guard node authenticated"
            |> TorLogger.Log

            let guard = new TorGuard(tcpClient, sslStream)
            do! guard.Handshake ipEndpoint

            ipEndpoint.ToString()
            |> sprintf "TorGuard: connection with %s established"
            |> TorLogger.Log

            guard.StartListening()

            return guard
        }

    static member NewClientAsync ipEndpoint =
        TorGuard.NewClient ipEndpoint |> Async.StartAsTask

    member self.Send (circuitId: uint16) (cellToSend: ICell) =
        async {
            let! sendResult =
                sendMailBox.PostAndAsyncReply(fun replyChannel ->
                    {
                        CircuitId = circuitId
                        CellToSend = cellToSend
                        ReplyChannel = replyChannel
                    }
                )

            match sendResult with
            | OperationResult.Ok _ -> return ()
            | OperationResult.Failure exn ->
                self.KillChildCircuits()
                return raise <| FSharpUtil.ReRaise exn
        }

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
                | None ->
                    return
                        raise
                        <| GuardConnectionFailedException
                            "Incomplete message header"
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
                    raise
                    <| GuardConnectionFailedException
                        "Socket got closed before receiving an expected cell"
            | Some(_circuitId, command, body) ->
                //FIXME: maybe continue instead of failing?
                if command <> expectedCommandType then
                    raise
                    <| GuardConnectionFailedException(
                        sprintf "Unexpected msg type %i" command
                    )

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

    member private __.KillChildCircuits() =
        TorLogger.Log "TorGuard: guard is dead, telling children..."

        shutdownToken.Cancel()

        let killCircuits() =
            circuitsMap
            |> Map.iter(fun _cid circuit -> circuit.HandleDestroyedGuard())

        lock circuitSetupLock killCircuits

    member private self.StartListening() =
        let rec readFromStream() =
            async {
                let! maybeCell =
                    async {
                        return!
                            ExceptionUtil.RunGuardJobWithExceptionHandling<Option<(uint16 * ICell)>>(
                                self.ReceiveMessage()
                            )
                    }

                match maybeCell with
                | None ->
                    self.KillChildCircuits()
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
                                    "TorGuard: exception when trying to handle incoming cell type=%i, ex=%s"
                                    cell.Command
                                    (ex.ToString())
                                |> TorLogger.Log

                                self.KillChildCircuits()
                        | None ->
                            self.KillChildCircuits()
                            failwithf "Unknown circuit, Id = %i" cid

                    return! readFromStream()
            }

        Async.Start(readFromStream(), shutdownToken.Token)

    member private self.Handshake(expectedIPEndPoint: IPEndPoint) =
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

            let expectedRouterAddress =
                let ipAddress = expectedIPEndPoint.Address

                {
                    RouterAddress.Type =
                        match ipAddress.AddressFamily with
                        | AddressFamily.InterNetwork -> 04uy //IPv4
                        | AddressFamily.InterNetworkV6 -> 06uy //IPv6
                        | _ ->
                            failwith
                                "Should not happen: router's IPAddress is not either v4 or v6"
                    Value = ipAddress.GetAddressBytes()
                }

            if netInfo.MyAddresses |> Seq.contains expectedRouterAddress |> not then
                raise
                <| GuardConnectionFailedException
                    "Expected router address is not listed in NETINFO"

            do!
                self.Send
                    Constants.DefaultCircuitId
                    {
                        //Clients SHOULD send "0" as their timestamp, to avoid fingerprinting.
                        CellNetInfo.Time = 0u
                        OtherAddress = expectedRouterAddress
                        MyAddresses = List.Empty
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
        member self.Dispose() =
            self.KillChildCircuits()
            sslStream.Dispose()
            client.Close()
            client.Dispose()
