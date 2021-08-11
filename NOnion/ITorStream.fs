namespace NOnion

open NOnion.Cells

type ITorStream =
    abstract HandleIncomingData : RelayData -> Async<unit>
