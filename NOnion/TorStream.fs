namespace NOnion

open FSharpx.Control.Observable

open NOnion.Cells
open FSharp.Control.Reactive
open System

type TorStream private (streamId: uint16, circuit: TorCircuit) =

    //TODO: don't use reactive, inherit stream instead.

    let window: TorWindow = TorWindow (500, 50)

    let handleFlowControl msg =
        match msg with
        | RelayData.RelayData data ->
            window.DeliverDecrease ()

            if window.NeedSendme () then
                circuit.Send streamId (RelayData.RelaySendMe)
                |> Async.RunSynchronously

        | RelaySendMe _ -> window.PackageIncrease ()
        | _ -> ()

        msg

    let streamNotCompleted msg =
        match msg with
        | RelayEnd _ -> false
        | _ -> true

    let takeDataCells msg =
        match msg with
        | RelayData data -> data |> Some
        | _ -> None

    let streamMessages =
        circuit.StreamMessages streamId
        |> Observable.map handleFlowControl
        |> Observable.takeWhile streamNotCompleted
        |> Observable.choose takeDataCells
        |> Observable.publish

    //TODO: dispose this
    let subscription = streamMessages.Connect ()

    member _.DataReceived = streamMessages :> IObservable<array<byte>>

    member self.Send (data: array<byte>) =
        async {
            let dataChunks =
                SeqUtils.chunk (Constants.MaximumRelayPayloadLength) data

            let rec sendChunks dataChunks =
                async {
                    match Seq.tryHead dataChunks with
                    | None -> ()
                    | Some (head) ->
                        do! circuit.Send streamId (RelayData.RelayData head)
                        window.PackageDecrease ()
                        do! Seq.tail dataChunks |> sendChunks
                }

            do! sendChunks dataChunks
        }

    member self.SendAsTask data =
        self.Send data |> Async.StartAsTask

    static member CreateDirectoryStream (circuit: TorCircuit) =
        async {
            let streamId = circuit.RegisterStreamId ()

            do! circuit.Send streamId (RelayData.RelayBeginDirectory)

            let! streamInitMsg =
                circuit.StreamMessages streamId |> Async.AwaitObservable

            return
                match streamInitMsg with
                | RelayConnected _ -> TorStream (streamId, circuit)
                | _ -> failwith "can't create a directory stream"
        }

    static member CreateDirectoryStreamAsTask circuit =
        TorStream.CreateDirectoryStream circuit |> Async.StartAsTask
