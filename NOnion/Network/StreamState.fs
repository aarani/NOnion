namespace NOnion.Network

open System.Threading.Tasks

type StreamState =
    | Initialized
    | Connecting of
        streamId: uint16 *
        completionTask: TaskCompletionSource<uint16>
    | Connected of streamId: uint16
    | Ended of reason: byte
