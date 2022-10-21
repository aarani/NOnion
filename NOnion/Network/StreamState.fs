﻿namespace NOnion.Network

open System.Threading.Tasks

open NOnion.Cells.Relay

type StreamState =
    | Initialized
    | Connecting of
        streamId: uint16 *
        completionTask: TaskCompletionSource<uint16>
    | Connected of streamId: uint16

    member self.Id =
        match self with
        | Connecting(streamId, _)
        | Connected streamId -> string streamId
        | Initialized -> "TBD"
