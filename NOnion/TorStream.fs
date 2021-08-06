namespace NOnion

open FSharpx.Control.Observable

open NOnion.Cells
open FSharp.Control.Reactive
open System
open System.Collections.Concurrent

type TorStream private (streamId: uint16, circuit: TorCircuit) =

    //TODO: don't use reactive, inherit stream instead.

    let window: TorWindow = TorWindow (500, 50)

    let finished = Event<byte> ()
    let newData = Event<array<byte>> ()

    let streamIdFilter (sid, message) =
        if sid = streamId then
            Some message
        else
            None

    do
        circuit.StreamMessages
        |> Event.choose streamIdFilter
        |> Event.add (fun message ->
            match message with
            | RelayData data ->
                window.DeliverDecrease ()

                if window.NeedSendme () then
                    circuit.Send streamId (RelayData.RelaySendMe)
                    |> Async.RunSynchronously

                newData.Trigger data
            | RelaySendMe _ -> window.PackageIncrease ()
            | RelayEnd reason -> finished.Trigger reason
            | _ -> ()
        )

    [<CLIEvent>]
    member self.DataReceived = newData.Publish

    [<CLIEvent>]
    member self.StreamCompleted = finished.Publish

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

            let streamInitMsg =
                circuit.StreamMessages
                |> Event.filter (fun (sid, _) -> sid = streamId)
                |> Event.map (fun (_, message) -> message)
                |> Event.choose (fun (message) ->
                    match message with
                    | RelayConnected _
                    | RelayEnd _ -> Some message
                    | _ -> None
                )
                |> Async.AwaitEvent

            do! circuit.Send streamId (RelayData.RelayBeginDirectory)

            let! streamInitMsg = streamInitMsg

            return
                match streamInitMsg with
                | RelayConnected _ -> TorStream (streamId, circuit)
                | _ -> failwith "can't create a directory stream"
        }

    static member CreateDirectoryStreamAsTask circuit =
        TorStream.CreateDirectoryStream circuit |> Async.StartAsTask
