namespace NOnion.Network

open System.Threading.Tasks

open NOnion.Cells.Relay

type StreamState =
    | Initialized
    | Connecting of
        streamId: uint16 *
        completionTask: TaskCompletionSource<uint16>
    | Connected of streamId: uint16
    | Ended of reason: EndReason
