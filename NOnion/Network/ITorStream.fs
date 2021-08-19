namespace NOnion.Network

open NOnion.Cells

type ITorStream =
    abstract HandleIncomingData : RelayData -> Async<unit>
