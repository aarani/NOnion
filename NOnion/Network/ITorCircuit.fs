﻿namespace NOnion.Network

open NOnion.Cells

type ITorCircuit =
    abstract HandleIncomingCell: ICell -> Async<unit>
    abstract HandleDestroyedGuard: unit -> unit
