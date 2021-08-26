namespace NOnion

open System

type GuardConnectionFailedException (innerException: Exception) =
    inherit Exception ("Connecting to guard node failed", innerException)

type CircuitTruncatedException (reason: byte) =
    inherit Exception (sprintf "Circuit got truncated, reason %i" reason)

type CircuitDestroyedException (reason: byte) =
    inherit Exception (sprintf "Circuit got destroyed, reason %i" reason)

exception CircuitTimeoutError
