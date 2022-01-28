namespace NOnion.Core

type DestroyReason =
    | None = 0uy
    | Protocol = 1uy
    | Internal = 2uy
    | Requested = 3uy
    | Hibernating = 4uy
    | ResourceLimit = 5uy
    | ConnectFailed = 6uy
    | OnionRouterIdentity = 7uy
    | ChannelClosed = 8uy
    | Finished = 9uy
    | Timeout = 10uy
    | Destoyed = 11uy
    | NoSuchService = 12uy
