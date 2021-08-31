namespace NOnion

open System

type CircuitTruncatedException (reason: byte) =
    inherit Exception (sprintf "Circuit got truncated, reason %i" reason)

type CircuitDestroyedException (reason: byte) =
    inherit Exception (sprintf "Circuit got destroyed, reason %i" reason)

exception TimeoutErrorException
