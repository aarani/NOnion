namespace NOnion

open NOnion.Cells

type ITorCircuit =
    abstract HandleIncomingCell : ICell -> Async<unit>
