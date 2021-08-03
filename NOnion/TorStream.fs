namespace NOnion


open System.Security.Cryptography
open FSharpx.Control.Observable

open NOnion.Cells
open NOnion.Utility
open FSharp.Control.Reactive
open System

type TorStream private (streamId: uint16, circuit: TorCircuit) as self =

    //TODO: don't use reactive, inherit stream instead.

    let window: TorWindow = TorWindow (500, 50)

    let streamMessages =
        circuit.StreamMessages streamId
        |> Observable.choose self.HandleMessage
        |> Observable.publish

    //TODO: dispose this
    let subscription = streamMessages.Connect ()

    member _.DataReceived = streamMessages :> IObservable<array<byte>>

    member self.HandleMessage (message: RelayData) =
        match message with
        | RelayData.RelayData data ->
            window.DeliverDecrease ()

            if window.NeedSendme () then
                circuit.Send streamId (RelayData.RelaySendMe)
                |> Async.RunSynchronously

            data |> Some
        | RelaySendMe _ ->
            window.PackageIncrease ()
            None
        | RelayEnd _ -> None
        | _ -> None


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
