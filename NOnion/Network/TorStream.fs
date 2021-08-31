namespace NOnion.Network

open System
open System.Threading.Tasks
open System.Threading.Tasks.Dataflow

open NOnion
open NOnion.Cells.Relay
open NOnion.Utility


type TorStream (circuit: TorCircuit) =

    let mutable streamState: StreamState = StreamState.Initialized
    let controlLock: SemaphoreLocker = SemaphoreLocker ()

    let window: TorWindow = TorWindow Constants.DefaultStreamLevelWindowParams

    let incomingCells: BufferBlock<RelayData> = BufferBlock<RelayData> ()
    let receiveLock: SemaphoreLocker = SemaphoreLocker ()

    member __.SendData (data: array<byte>) =
        async {
            let safeSend () =
                async {
                    match streamState with
                    | Connected streamId ->
                        let dataChunks =
                            SeqUtils.Chunk
                                Constants.MaximumRelayPayloadLength
                                data

                        let rec sendChunks dataChunks =
                            async {
                                match Seq.tryHead dataChunks with
                                | None -> ()
                                | Some head ->
                                    circuit.LastNode.Window.PackageDecrease ()

                                    do!
                                        circuit.SendRelayCell
                                            streamId
                                            (head
                                             |> Array.ofSeq
                                             |> RelayData.RelayData)
                                            None

                                    window.PackageDecrease ()
                                    do! Seq.tail dataChunks |> sendChunks
                            }

                        do! sendChunks dataChunks
                    | _ ->
                        failwith
                            "Unexpected state when trying to send data over stream"
                }

            return! controlLock.RunAsyncWithSemaphore safeSend
        }

    member self.SendDataAsync data =
        self.SendData data |> Async.StartAsTask

    member self.ConnectToDirectory () =
        async {
            let startConnectionProcess () =
                async {
                    let streamId = circuit.RegisterStream self

                    let tcs = TaskCompletionSource ()

                    streamState <- Connecting (streamId, tcs)

                    do!
                        circuit.SendRelayCell
                            streamId
                            RelayData.RelayBeginDirectory
                            None

                    return tcs.Task
                }

            let! connectionProcessTcs =
                controlLock.RunAsyncWithSemaphore startConnectionProcess

            return! connectionProcessTcs |> Async.AwaitTask
        }

    member self.ConnectToDirectoryAsync () =
        self.ConnectToDirectory () |> Async.StartAsTask

    member self.Receive () =
        async {
            let safeReceive () =
                async {
                    let! cell = incomingCells.ReceiveAsync () |> Async.AwaitTask

                    match cell with
                    | RelayData data -> return data |> Some
                    | RelayEnd reason -> return None
                    | _ ->
                        return
                            failwith
                                "IncomingCells should not keep non-related cells"
                }

            return! receiveLock.RunAsyncWithSemaphore safeReceive
        }

    member self.ReceiveAsync () =
        self.Receive () |> Async.StartAsTask

    interface ITorStream with
        member __.HandleIncomingData (message: RelayData) =
            async {
                match message with
                | RelayConnected _ ->
                    let handleRelayConnected () =
                        match streamState with
                        | Connecting (streamId, tcs) ->
                            streamState <- Connected streamId
                            tcs.SetResult streamId
                        | _ ->
                            failwith
                                "Unexpected state when receiving RelayConnected cell"


                    controlLock.RunSyncWithSemaphore handleRelayConnected
                | RelayData data ->
                    window.DeliverDecrease ()

                    if window.NeedSendme () then
                        let sendSendMe () =
                            async {
                                match streamState with
                                | Connected streamId ->
                                    return!
                                        circuit.SendRelayCell
                                            streamId
                                            RelayData.RelaySendMe
                                            None
                                | _ ->
                                    failwith
                                        "Unexpected state when sending stream-level sendme"
                            }

                        do! controlLock.RunAsyncWithSemaphore sendSendMe

                    incomingCells.Post message |> ignore<bool>
                | RelaySendMe _ -> window.PackageIncrease ()
                | RelayEnd reason ->
                    let handleRelayEnd () =
                        match streamState with
                        | Connecting (_, tcs) ->
                            streamState <- Ended reason

                            Failure (
                                sprintf
                                    "Stream connection process failed! Reason: %d"
                                    reason
                            )
                            |> tcs.SetException
                        | Connected _ ->
                            incomingCells.Post message |> ignore<bool>
                            streamState <- Ended reason
                        | _ ->
                            failwith
                                "Unexpected state when receiving RelayEnd cell"

                    controlLock.RunSyncWithSemaphore handleRelayEnd
                | _ -> ()
            }
