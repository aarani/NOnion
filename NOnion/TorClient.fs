namespace NOnion

open System
open System.IO
open System.Threading
open System.Security.Authentication
open System.Net
open System.Net.Sockets
open System.Net.Security

open NOnion.Cells
open NOnion.Crypto
open NOnion.Crypto.Kdf
open NOnion.Utility

type TorGuard () =
    let shutdownToken = new CancellationTokenSource ()

    let client = new TcpClient ()

    let mutable state: GuardState = GuardState.Initialized
    let controlLock: obj = obj ()

    let mutable circuitIds: list<uint16> = List.empty
    let mutable circuitsMap: Map<uint16, TorCircuit> = Map.empty
    (* Prevents two circuit setup happening at once (to prevent race condition on writing to CircuitIds list or circuitsMap map) *)
    let circuitSetupLock: obj = obj ()

    member self.Connect (remoteAddress: IPEndPoint) =
        async {
            let handshake () =
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
                    do!
                        self.ReceiveExcpected<CellAuthChallenge> ()
                        |> Async.Ignore

                    let! netInfo = self.ReceiveExcpected<CellNetInfo> ()

                    do!
                        self.Send
                            0us
                            {
                                CellNetInfo.Time =
                                    DateTimeUtils.ToUnixTimestamp
                                        DateTime.UtcNow
                                OtherAddress = netInfo.MyAddresses |> Seq.head
                                MyAddresses = [ netInfo.OtherAddress ]
                            }

                    let versionOpt =
                        version.Versions
                        |> SeqUtils.intersection
                            Constants.SupportedProtocolVersion
                        |> List.tryHead

                    return
                        match versionOpt with
                        | Some version -> version
                        | None -> failwith "no compatible version with the node"
                }

            match state with
            | Initialized ->
                Monitor.Enter controlLock

                try
                    do!
                        client.ConnectAsync (
                            remoteAddress.Address,
                            remoteAddress.Port
                        )
                        |> Async.AwaitTask

                    let sslStream =
                        new SslStream (
                            client.GetStream (),
                            false,
                            fun _ _ _ _ -> true
                        )

                    state <- Connecting sslStream

                    do!
                        sslStream.AuthenticateAsClientAsync (
                            String.Empty,
                            null,
                            SslProtocols.Tls12,
                            false
                        )
                        |> Async.AwaitTask

                    let! version = handshake ()

                    state <- Connected (sslStream, version)
                finally
                    Monitor.Exit controlLock
            | _ -> failwith "//TODO: error message here"
        }

    //TODO: handle version
    member self.Send (circuidId: uint16) (cellToSend: ICell) =
        async {
            match state with
            | Connected (sslStream, _)
            | Connecting sslStream when circuidId = 0us ->
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

                do! sslStream.FlushAsync () |> Async.AwaitTask

            | _ ->
                failwith (
                    sprintf
                        "guard is not ready to receive any data: %s"
                        (state.ToString ())
                )
        }

    member private self.StartListening () =
        let listeningJob () =
            async {
                match state with
                | Connected (sslStream, _) when sslStream.CanRead ->
                    let! (cid, payload) = self.ReceiveMessage ()

                    if cid = 0us then
                        //TODO: handle control message?
                        ()
                    else
                        match circuitsMap.TryFind cid with
                        | Some circuit -> do! circuit.HandleIncomingCell payload
                        | None -> failwith "Unknown circuit"

                    ()
                | Connected (sslStream, _) when not sslStream.CanRead ->
                    lock controlLock (fun () -> state <- Disconnected)
                | _ ->
                    failwith (
                        sprintf
                            "guard is not ready to receive any data: %s"
                            (state.ToString ())
                    )
            }

        Async.Start (listeningJob (), shutdownToken.Token)
    //TODO: set state to disconnected if we can't read anymore
    member private self.ReceiveExcpected<'T when 'T :> ICell> () : Async<'T> =
        async {
            match state with
            | Connecting sslStream ->
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
            | _ ->
                return
                    failwith (
                        sprintf "Unexpected state: %s" (state.ToString ())
                    )
        }

    member private self.ReceiveMessage () =
        async {
            match state with
            | Connected (sslStream, _) ->
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
            | _ ->
                return
                    failwith (
                        sprintf
                            "guard is not ready to receive any data: %s"
                            (state.ToString ())
                    )
        }

    member internal self.RegisterCircuitId (cid: uint16) : bool =
        let safeRegister () =
            if List.contains cid circuitIds then
                false
            else
                circuitIds <- circuitIds @ [ cid ]
                true

        lock circuitSetupLock safeRegister

    member internal self.RegisterCircuitHandler
        (cid: uint16)
        (circuit: TorCircuit)
        =
        let safeRegister () =
            circuitsMap <- circuitsMap.Add (cid, circuit)

        lock circuitSetupLock safeRegister

    interface IDisposable with
        member self.Dispose () =
            shutdownToken.Cancel ()

            match state with
            | Connected (sslStream, _)
            | Connecting sslStream -> sslStream.Dispose ()
            | _ -> ()

            client.Dispose ()

and TorCircuit internal (guard: TorGuard) =

    let mutable state: CircuitState = CircuitState.Initialized
    let controlLock: obj = obj ()

    // Circuit-level flow-control
    let window = TorWindow (1000, 100)

    let mutable streamsCount: int = 1
    let mutable streamsMap: Map<uint16, TorStream> = Map.empty
    (* Prevents two stream setup happening at once (to prevent race condition on writing to StreamIds list and streamsMap map) *)
    let streamSetupLock: obj = obj ()

    member self.SendRelayCell (streamId: uint16) (relayData: RelayData) =
        async {
            match state with
            | Created (id, cryptoState) ->
                let plainRelayCell =
                    CellPlainRelay.Create
                        streamId
                        relayData
                        (Array.zeroCreate 4)

                let relayPlainBytes = plainRelayCell.ToBytes true

                cryptoState.ForwardDigest.Update
                    relayPlainBytes
                    0
                    relayPlainBytes.Length

                let digest =
                    cryptoState.ForwardDigest.GetDigestBytes () |> Array.take 4

                let plainRelayCell =
                    { plainRelayCell with
                        Digest = digest
                    }

                window.PackageDecrease ()

                do!
                    {
                        CellEncryptedRelay.EncryptedData =
                            plainRelayCell.ToBytes false
                            |> cryptoState.ForwardCipher.Encrypt
                    }
                    |> guard.Send id
            | _ ->
                return
                    failwith (
                        sprintf
                            "Circuit's state is non-optimal: %s"
                            (state.ToString ())
                    )
        }

    member self.HandleIncomingRelayCell
        (encryptedRelayCell: CellEncryptedRelay)
        =
        async {
            match state with
            | Created (_id, cryptoState) ->
                let decryptedRelayCellBytes =
                    cryptoState.BackwardCipher.Encrypt
                        encryptedRelayCell.EncryptedData

                let recognized =
                    System.BitConverter.ToUInt16 (decryptedRelayCellBytes, 1)

                if recognized <> 0us then
                    failwith "wat?"

                let digest =
                    decryptedRelayCellBytes |> Array.skip 5 |> Array.take 4

                Array.fill decryptedRelayCellBytes 5 4 0uy

                let computedDigest =
                    cryptoState.BackwardDigest.PeekDigest
                        decryptedRelayCellBytes
                        0
                        decryptedRelayCellBytes.Length
                    |> Array.take 4

                if digest <> computedDigest then
                    failwith "wat"

                cryptoState.BackwardDigest.Update
                    decryptedRelayCellBytes
                    0
                    decryptedRelayCellBytes.Length

                let decryptedRelayCell =
                    CellPlainRelay.FromBytes decryptedRelayCellBytes

                match decryptedRelayCell.Data with
                | RelayData.RelayData _ ->
                    window.DeliverDecrease ()

                    if window.NeedSendme () then
                        do! self.SendRelayCell 0us RelayData.RelaySendMe
                | RelaySendMe _ when decryptedRelayCell.StreamId = 0us ->
                    window.PackageIncrease ()
                | _ -> ()

            //TODO: send to stream
            | _ ->
                return
                    failwith (
                        sprintf
                            "Received relay cell with unexpected state: %s"
                            (state.ToString ())
                    )
        }

    member self.HandleCreatedFast (createdMsg: CellCreatedFast) =
        async {
            Monitor.Enter controlLock

            try
                match state with
                | CreatingFast (cid, randomClientMaterial) ->
                    let kdfResult =
                        Array.concat [ randomClientMaterial
                                       createdMsg.Y ]
                        |> Kdf.computeLegacyKdf

                    if kdfResult.KeyHandshake <> createdMsg.DerivativeKeyData then
                        failwith "Bad key handshake"

                    let cryptoState = TorCryptoState.FromKdfResult kdfResult

                    state <- Created (cid, cryptoState)
                | _ ->
                    return
                        failwith (
                            sprintf "Unexpected state: %s" (state.ToString ())
                        )
            finally
                Monitor.Exit controlLock
        }

    member self.HandleIncomingCell (cell: ICell) =
        async {
            match cell with
            | :? CellEncryptedRelay as relayCell ->
                do! self.HandleIncomingRelayCell relayCell
            | :? CellCreatedFast as creationResult ->
                do! self.HandleCreatedFast creationResult
            | _ -> ()
        }

    member internal self.RegisterStream (stream: TorStream) : uint16 =
        let safeRegister () =
            let newId = uint16 streamsCount
            streamsCount <- streamsCount + 1
            streamsMap <- streamsMap.Add (newId, stream)
            newId

        lock streamSetupLock safeRegister

and TorStream internal (circuit: TorCircuit) as self =
    let window: TorWindow = TorWindow (500, 50)
    let streamId = circuit.RegisterStream self
