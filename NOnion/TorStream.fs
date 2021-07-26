namespace NOnion


open System.Security.Cryptography
open FSharpx.Control.Observable

open NOnion.Cells
open NOnion.Utility

type TorStream private (streamId: uint16, circuit: TorCircuit) =

    member self.DataReceived =
        circuit.StreamMessages streamId
        |> Observable.choose
            (function
            | RelayData.RelayData data -> Some data
            | _ -> None)

    member self.Send (data: array<byte>) =
        async {
            let dataChunks =
                SeqUtils.chunk (Constants.FixedPayloadLength - 11) data

            let rec sendChunks dataChunks =
                async {
                    match Seq.tryHead dataChunks with
                    | None -> ()
                    | Some (head) ->
                        do! circuit.Send streamId (RelayData.RelayData head)
                        do! Seq.tail dataChunks |> sendChunks
                }

            do! sendChunks dataChunks
        }
        |> Async.StartAsTask

    static member CreateDirectoryStream (circuit: TorCircuit) =
        async {
            let rec createStreamId (retry: int) =
                if retry >= Constants.MaxCircuitIdGenerationRetry then
                    failwith "can't create a circuit"

                let randomBytes = Array.zeroCreate<byte> 2

                RandomNumberGenerator
                    .Create()
                    .GetBytes randomBytes

                let sid =
                    IntegerSerialization.FromBigEndianByteArrayToUInt16
                        randomBytes

                if circuit.RegisterStreamId sid then
                    sid
                else
                    createStreamId (retry + 1)

            let streamId = createStreamId 0

            do! circuit.Send streamId (RelayData.RelayBeginDirectory)

            let! streamInitMsg =
                circuit.StreamMessages streamId |> Async.AwaitObservable

            return
                match streamInitMsg with
                | RelayConnected _ -> TorStream (streamId, circuit)
                | _ -> failwith "can't create a directory stream"
        }
        |> Async.StartAsTask
