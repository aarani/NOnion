namespace NOnion.Core.Network

open System.Threading.Tasks

open NOnion.Core.Cells.Relay

type StreamState =
    | Initialized
    | Connecting of
        streamId: uint16 *
        completionTask: TaskCompletionSource<uint16>
    | Connected of streamId: uint16
    | Ended of streamId: uint16 * reason: EndReason

    member self.Id =
        match self with
        | Connecting(streamId, _)
        | Connected streamId
        | Ended(streamId, _) -> string streamId
        | Initialized -> "TBD"
