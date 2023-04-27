﻿namespace NOnion.Network

open System
open System.Threading.Tasks
open System.Threading.Tasks.Dataflow

open FSharpx.Collections

open NOnion
open NOnion.Cells.Relay
open NOnion.Utility
open MailboxResultUtil

type private StreamReceiveMessage =
    {
        StreamBuffer: array<byte>
        BufferOffset: int
        BufferLength: int
        ReplyChannel: AsyncReplyChannel<OperationResult<int>>
    }

type private StreamControlMessage =
    | End of replyChannel: AsyncReplyChannel<OperationResult<unit>>
    | Send of
        array<byte> *
        replyChannel: AsyncReplyChannel<OperationResult<unit>>
    | StartStreamConnectionProcess of
        address: string *
        streamObj: ITorStream *
        replyChannel: AsyncReplyChannel<OperationResult<Task<uint16>>>
    | StartDirectoryConnectionProcess of
        streamObj: ITorStream *
        replyChannel: AsyncReplyChannel<OperationResult<Task<uint16>>>
    | RegisterStream of
        streamObj: ITorStream *
        streamId: uint16 *
        replyChannel: AsyncReplyChannel<OperationResult<unit>>
    | HandleRelayConnected of
        replyChannel: AsyncReplyChannel<OperationResult<unit>>
    | HandleRelayEnd of
        message: RelayData *
        reason: EndReason *
        replyChannelOpt: Option<AsyncReplyChannel<OperationResult<unit>>>
    | SendSendMe of replyChannel: AsyncReplyChannel<OperationResult<unit>>

type TorStream(circuit: TorCircuit) =

    let mutable streamState: StreamState = StreamState.Initialized

    let window: TorWindow = TorWindow Constants.DefaultStreamLevelWindowParams

    let mutable currentBuffer: array<byte> =
        Array.zeroCreate Constants.MaximumRelayPayloadLength

    let mutable bufferOffset: int = 0
    let mutable bufferLength: int = 0
    let mutable isEOF: bool = false

    let incomingCells: BufferBlock<RelayData> = BufferBlock<RelayData>()

    let rec StreamControlMailBoxProcessor
        (inbox: MailboxProcessor<StreamControlMessage>)
        =
        let safeEnd() =
            async {
                match streamState with
                | Connected streamId ->
                    do!
                        circuit.SendRelayCell
                            streamId
                            (RelayEnd EndReason.Done)
                            None

                    sprintf
                        "TorStream[%i,%i]: sending stream end packet"
                        streamId
                        circuit.Id
                    |> TorLogger.Log
                | _ -> failwith "Unexpected state when trying to end the stream"
            }

        let safeSend(data: array<byte>) =
            async {
                match streamState with
                | Connected streamId ->
                    let dataChunks =
                        SeqUtils.Chunk Constants.MaximumRelayPayloadLength data

                    let rec sendChunks dataChunks =
                        async {
                            match Seq.tryHeadTail dataChunks with
                            | None -> ()
                            | Some(head, nextDataChunks) ->
                                let! lastNode = circuit.GetLastNode()
                                lastNode.Window.PackageDecrease()

                                do!
                                    circuit.SendRelayCell
                                        streamId
                                        (head
                                         |> Array.ofSeq
                                         |> RelayData.RelayData)
                                        None

                                window.PackageDecrease()
                                do! nextDataChunks |> sendChunks
                        }

                    do! sendChunks dataChunks
                | _ ->
                    failwith
                        "Unexpected state when trying to send data over stream"
            }

        let startStreamConnectionProcess
            (address: string)
            (streamObj: ITorStream)
            =
            async {
                let streamId = circuit.RegisterStream streamObj None

                let tcs = TaskCompletionSource()

                streamState <- Connecting(streamId, tcs)

                sprintf
                    "TorStream[%i,%i]: creating a hidden service stream"
                    streamId
                    circuit.Id
                |> TorLogger.Log

                do!
                    circuit.SendRelayCell
                        streamId
                        (RelayBegin
                            {
                                RelayBegin.Address = address
                                Flags = 0u
                            })
                        None

                return tcs.Task
            }

        let startDirectoryConnectionProcess(streamObj: ITorStream) =
            async {
                let streamId = circuit.RegisterStream streamObj None

                let tcs = TaskCompletionSource()

                streamState <- Connecting(streamId, tcs)

                sprintf
                    "TorStream[%i,%i]: creating a directory stream"
                    streamId
                    circuit.Id
                |> TorLogger.Log

                do!
                    circuit.SendRelayCell
                        streamId
                        RelayData.RelayBeginDirectory
                        None

                return tcs.Task
            }

        let registerProcess (streamObj: ITorStream) (streamId: uint16) =
            streamState <-
                circuit.RegisterStream streamObj (Some streamId) |> Connected

        let handleRelayConnected() =
            match streamState with
            | Connecting(streamId, tcs) ->
                streamState <- Connected streamId
                tcs.SetResult streamId

                sprintf "TorStream[%i,%i]: connected!" streamId circuit.Id
                |> TorLogger.Log
            | _ ->
                failwith "Unexpected state when receiving RelayConnected cell"

        let handleRelayEnd (message: RelayData) (reason: EndReason) =
            match streamState with
            | Connecting(streamId, tcs) ->
                sprintf
                    "TorStream[%i,%i]: received end packet while connecting"
                    streamId
                    circuit.Id
                |> TorLogger.Log

                Failure(
                    sprintf
                        "Stream connection process failed! Reason: %s"
                        (reason.ToString())
                )
                |> tcs.SetException
            | Connected streamId ->
                sprintf
                    "TorStream[%i,%i]: received end packet while connected"
                    streamId
                    circuit.Id
                |> TorLogger.Log

                incomingCells.Post message |> ignore<bool>
            | _ -> failwith "Unexpected state when receiving RelayEnd cell"

        let sendSendMe() =
            async {
                match streamState with
                | Connected streamId ->
                    return!
                        circuit.SendRelayCell
                            streamId
                            RelayData.RelaySendMe
                            None
                | _ ->
                    failwith "Unexpected state when sending stream-level sendme"
            }

        async {
            let! cancellationToken = Async.CancellationToken
            cancellationToken.ThrowIfCancellationRequested()

            let! command = inbox.Receive()

            match command with
            | End replyChannel ->
                do! safeEnd() |> TryExecuteAsyncAndReplyAsResult replyChannel
            | Send(data, replyChannel) ->
                do!
                    safeSend data
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | StartStreamConnectionProcess(address, streamObj, replyChannel) ->
                do!
                    startStreamConnectionProcess address streamObj
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | StartDirectoryConnectionProcess(streamObj, replyChannel) ->
                do!
                    startDirectoryConnectionProcess(streamObj)
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | RegisterStream(streamObj, streamId, replyChannel) ->
                TryExecuteAndReplyAsResult
                    replyChannel
                    (fun _ -> registerProcess streamObj streamId)
            | HandleRelayConnected replyChannel ->
                TryExecuteAndReplyAsResult replyChannel handleRelayConnected
            | HandleRelayEnd(message, reason, replyChannelOpt) ->
                match replyChannelOpt with
                | Some replyChannel ->
                    TryExecuteAndReplyAsResult
                        replyChannel
                        (fun _ -> handleRelayEnd message reason)
                | None -> handleRelayEnd message reason
            | SendSendMe replyChannel ->
                do! sendSendMe() |> TryExecuteAsyncAndReplyAsResult replyChannel

            return! StreamControlMailBoxProcessor inbox
        }

    let streamControlMailBox =
        MailboxProcessor.Start StreamControlMailBoxProcessor

    let rec StreamReceiveMailBoxProcessor
        (inbox: MailboxProcessor<StreamReceiveMessage>)
        =
        let currentBufferHasRemainingBytes() =
            bufferLength > bufferOffset

        let currentBufferRemainingBytes() =
            bufferLength - bufferOffset

        let readFromCurrentBuffer
            (buffer: array<byte>)
            (offset: int)
            (len: int)
            =
            let readLength = min len (currentBufferRemainingBytes())
            Array.blit currentBuffer bufferOffset buffer offset readLength
            bufferOffset <- bufferOffset + readLength

            readLength

        let processIncomingCell() =
            async {
                let! nextCell = incomingCells.ReceiveAsync() |> Async.AwaitTask

                match nextCell with
                | RelayData data ->
                    Array.blit data 0 currentBuffer 0 data.Length
                    bufferOffset <- 0
                    bufferLength <- data.Length

                    window.DeliverDecrease()

                    if window.NeedSendme() then

                        let! sendResult =
                            streamControlMailBox.PostAndAsyncReply
                                StreamControlMessage.SendSendMe

                        return UnwrapResult sendResult

                | RelayEnd reason when reason = EndReason.Done ->
                    TorLogger.Log(
                        sprintf
                            "TorStream[%i]: pushed EOF to consumer"
                            circuit.Id
                    )

                    currentBuffer <- Array.empty
                    bufferOffset <- 0
                    bufferLength <- 0
                    isEOF <- true

                | RelayEnd reason ->
                    return
                        failwithf
                            "Stream closed unexpectedly, reason = %s"
                            (reason.ToString())
                | _ ->
                    return
                        failwith "IncomingCells should not keep unrelated cells"
            }

        let rec fillBuffer() =
            async {
                do! processIncomingCell()

                if isEOF || currentBufferHasRemainingBytes() then
                    return ()
                else
                    return! fillBuffer()
            }

        let refillBufferIfNeeded() =
            async {
                if not isEOF then
                    if currentBufferHasRemainingBytes() then
                        return ()
                    else
                        return! fillBuffer()
            }


        let safeReceive(buffer: array<byte>, offset: int, length: int) =
            async {
                if length = 0 then
                    return 0
                else
                    do! refillBufferIfNeeded()

                    if isEOF then
                        return -1
                    else
                        let rec tryRead bytesRead bytesRemaining =
                            async {
                                if bytesRemaining > 0 && not isEOF then
                                    do! refillBufferIfNeeded()

                                    let newBytesRead =
                                        bytesRead
                                        + (readFromCurrentBuffer
                                            buffer
                                            (offset + bytesRead)
                                            (length - bytesRead))

                                    let newBytesRemaining =
                                        length - newBytesRead

                                    if incomingCells.Count = 0 then
                                        return newBytesRead
                                    else
                                        return!
                                            tryRead
                                                newBytesRead
                                                newBytesRemaining
                                else
                                    return bytesRead
                            }

                        return! tryRead 0 length
            }


        async {
            let! cancellationToken = Async.CancellationToken
            cancellationToken.ThrowIfCancellationRequested()

            let! {
                     StreamBuffer = buffer
                     BufferOffset = offset
                     BufferLength = length
                     ReplyChannel = replyChannel
                 } = inbox.Receive()

            do!
                safeReceive(buffer, offset, length)
                |> TryExecuteAsyncAndReplyAsResult replyChannel

            return! StreamReceiveMailBoxProcessor inbox
        }

    let streamReceiveMailBox =
        MailboxProcessor.Start StreamReceiveMailBoxProcessor

    static member Accept (streamId: uint16) (circuit: TorCircuit) =
        async {
            let stream = TorStream circuit
            do! stream.RegisterIncomingStream streamId

            do! circuit.SendRelayCell streamId (RelayConnected Array.empty) None

            sprintf
                "TorStream[%i,%i]: incoming stream accepted"
                streamId
                circuit.Id
            |> TorLogger.Log

            return stream
        }

    member __.End() =
        async {
            let! sendResult =
                streamControlMailBox.PostAndAsyncReply StreamControlMessage.End

            return UnwrapResult sendResult
        }

    member self.EndAsync() =
        self.End() |> Async.StartAsTask


    member __.SendData(data: array<byte>) =
        async {
            let! sendResult =
                streamControlMailBox.PostAndAsyncReply(fun replyChannel ->
                    StreamControlMessage.Send(data, replyChannel)
                )

            return UnwrapResult sendResult
        }

    member self.SendDataAsync data =
        self.SendData data |> Async.StartAsTask

    member self.ConnectToService(port: int) =
        async {
            let! completionTaskRes =
                streamControlMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        StreamControlMessage.StartStreamConnectionProcess(
                            sprintf ":%i" port,
                            self,
                            replyChannel
                        )
                    ),
                    Constants.StreamCreationTimeout.TotalMilliseconds |> int
                )

            return!
                completionTaskRes
                |> UnwrapResult
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.StreamCreationTimeout
        }

    member self.ConnectToDirectory() =
        async {
            let! completionTaskResult =
                streamControlMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        StreamControlMessage.StartDirectoryConnectionProcess(
                            self,
                            replyChannel
                        )
                    ),
                    Constants.StreamCreationTimeout.TotalMilliseconds |> int
                )

            return!
                completionTaskResult
                |> UnwrapResult
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.StreamCreationTimeout
        }

    member self.ConnectToDirectoryAsync() =
        self.ConnectToDirectory() |> Async.StartAsTask

    member self.ConnectToOutside (address: string) (port: int) =
        async {
            let! completionTaskRes =
                streamControlMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        StreamControlMessage.StartStreamConnectionProcess(
                            sprintf "%s:%i" address port,
                            self,
                            replyChannel
                        )
                    ),
                    Constants.StreamCreationTimeout.TotalMilliseconds |> int
                )

            return!
                completionTaskRes
                |> UnwrapResult
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.StreamCreationTimeout
        }

    member self.ConnectToOutsideAsync(address, port) =
        self.ConnectToOutside address port |> Async.StartAsTask

    member private self.RegisterIncomingStream(streamId: uint16) =
        async {
            let! registerationResult =
                streamControlMailBox.PostAndAsyncReply(fun replyChannel ->
                    StreamControlMessage.RegisterStream(
                        self,
                        streamId,
                        replyChannel
                    )
                )

            return UnwrapResult registerationResult
        }

    member self.Receive (buffer: array<byte>) (offset: int) (length: int) =
        async {
            let! receiveResult =
                streamReceiveMailBox.PostAndAsyncReply(fun replyChannel ->
                    {
                        StreamBuffer = buffer
                        BufferOffset = offset
                        BufferLength = length
                        ReplyChannel = replyChannel
                    }
                )

            return UnwrapResult receiveResult
        }

    member self.ReceiveAsync(buffer: array<byte>, offset: int, length: int) =
        self.Receive buffer offset length |> Async.StartAsTask

    interface ITorStream with
        member __.HandleDestroyedCircuit() =
            TorLogger.Log
                "TorStream: circuit got destroyed, faking received relay end cell"

            streamControlMailBox.Post(
                StreamControlMessage.HandleRelayEnd(
                    RelayEnd EndReason.Destroy,
                    EndReason.Destroy,
                    None
                )
            )

        member __.HandleIncomingData(message: RelayData) =
            async {
                match message with
                | RelayConnected _ ->
                    let! handleConnectedResult =
                        streamControlMailBox.PostAndAsyncReply
                            StreamControlMessage.HandleRelayConnected

                    return UnwrapResult handleConnectedResult
                | RelayData _ -> incomingCells.Post message |> ignore<bool>
                | RelaySendMe _ -> window.PackageIncrease()
                | RelayEnd reason ->
                    let! handleEndResult =
                        streamControlMailBox.PostAndAsyncReply(fun replyChannel ->
                            StreamControlMessage.HandleRelayEnd(
                                message,
                                reason,
                                Some replyChannel
                            )
                        )

                    return UnwrapResult handleEndResult
                | _ -> ()
            }
