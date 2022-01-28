namespace NOnion.Core.Network

open NOnion.Core.Cells

type ITorCircuit =
    abstract HandleIncomingCell: ICell -> Async<unit>
