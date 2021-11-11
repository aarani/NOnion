namespace NOnion.Network

open NOnion.Cells.Relay

type ITorStream =
    abstract HandleIncomingData: RelayData -> Async<unit>
