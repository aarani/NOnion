namespace NOnion

open System
open System.Reactive.Subjects

open FSharpx.Control.Observable

open NOnion.Cells
open NOnion.Utility

type TorStream private (streamId: uint16, circuit: TorCircuit) as self =

    let window: TorWindow = TorWindow Constants.DefaultStreamLevelWindowParams

    let streamMessagesSubject = new Subject<array<byte>> ()

    let subscription =
        circuit.StreamsMessages
        |> ObservableUtils.FilterByKey streamId
        |> Observable.subscribe self.HandleIncomingMessage

    member __.DataReceived = streamMessagesSubject :> IObservable<array<byte>>

    member __.Send (data: array<byte>) =
        async {
            let dataChunks =
                SeqUtils.chunk Constants.MaximumRelayPayloadLength data

            let rec sendChunks dataChunks =
                async {
                    match Seq.tryHead dataChunks with
                    | None -> ()
                    | Some head ->
                        do!
                            head
                            |> Array.ofSeq
                            |> RelayData.RelayData
                            |> circuit.Send streamId

                        window.PackageDecrease ()
                        do! Seq.tail dataChunks |> sendChunks
                }

            do! sendChunks dataChunks
        }

    member self.SendAsync data =
        self.Send data |> Async.StartAsTask

    member __.HandleIncomingMessage (message: RelayData) =
        match message with
        | RelayData data ->
            window.DeliverDecrease ()

            if window.NeedSendme () then
                circuit.Send streamId RelayData.RelaySendMe
                |> Async.RunSynchronously

            streamMessagesSubject.OnNext data
        | RelaySendMe _ -> window.PackageIncrease ()
        | RelayEnd _ -> streamMessagesSubject.OnCompleted ()
        | _ -> ()

    static member CreateDirectoryStream (circuit: TorCircuit) =
        async {
            let streamId = circuit.RegisterStreamId ()

            // We start the handler before we send the Begin request to make sure we don't miss the init event

            let streamInitMsg =
                circuit.StreamsMessages
                |> ObservableUtils.FilterByKey streamId
                |> Observable.choose (fun message ->
                    match message with
                    | RelayConnected _
                    | RelayEnd _ -> Some message
                    | _ -> None
                )
                |> Async.AwaitObservable

            do! circuit.Send streamId RelayData.RelayBeginDirectory

            let! streamInitMsg = streamInitMsg

            return
                match streamInitMsg with
                | RelayConnected _ -> new TorStream (streamId, circuit)
                | _ -> failwith "can't create a directory stream"
        }

    static member CreateDirectoryStreamAsync circuit =
        TorStream.CreateDirectoryStream circuit |> Async.StartAsTask

    interface IDisposable with
        member __.Dispose () =
            subscription.Dispose ()
            streamMessagesSubject.OnCompleted ()
            streamMessagesSubject.Dispose ()
