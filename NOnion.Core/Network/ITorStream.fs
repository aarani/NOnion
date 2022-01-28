namespace NOnion.Core.Network

open NOnion.Core.Cells.Relay

type ITorStream =
    abstract HandleIncomingData: RelayData -> Async<unit>
