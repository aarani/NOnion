namespace NOnion

open System

type NOnionException =
    inherit Exception

    new(msg: string) = { inherit Exception(msg) }

    new(msg: string, innerException: Exception) =
        { inherit Exception(msg, innerException) }

type GuardConnectionFailedException(innerException: Exception) =
    inherit NOnionException("Connecting to guard node failed", innerException)

type CircuitTruncatedException(reason: DestroyReason) =
    inherit NOnionException(sprintf "Circuit got truncated, reason %A" reason)

type CircuitDestroyedException(reason: DestroyReason) =
    inherit NOnionException(sprintf "Circuit got destroyed, reason %A" reason)

type GuardDisconnectionException() =
    inherit NOnionException("Guard got disconnected")

type TimeoutErrorException() =
    inherit NOnionException("Time limit exceeded for operation")

type UnsuccessfulHttpRequestException(statusCode: string) =
    inherit NOnionException(sprintf
                                "Non-200 status code received, code: %s"
                                statusCode)
