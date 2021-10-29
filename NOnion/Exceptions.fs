namespace NOnion

open System

type GuardConnectionFailedException(innerException: Exception) =
    inherit Exception("Connecting to guard node failed", innerException)

type CircuitTruncatedException(reason: DestroyReason) =
    inherit Exception(sprintf "Circuit got truncated, reason %A" reason)

type CircuitDestroyedException(reason: DestroyReason) =
    inherit Exception(sprintf "Circuit got destroyed, reason %A" reason)

exception TimeoutErrorException
