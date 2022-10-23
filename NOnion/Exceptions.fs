namespace NOnion

open System

type NOnionException =
    inherit Exception

    internal new(msg: string) = { inherit Exception(msg) }

    internal new(msg: string, innerException: Exception) =
        { inherit Exception(msg, innerException) }

type GuardConnectionFailedException =
    inherit NOnionException

    internal new(innerException: Exception) =
        { inherit NOnionException("Connecting to guard node failed",
                                  innerException) }

    internal new(message: string) =
        { inherit NOnionException("Connecting to guard node failed: " + message) }

type CircuitTruncatedException internal (reason: DestroyReason) =
    inherit NOnionException(sprintf "Circuit got truncated, reason %A" reason)

type CircuitDestroyedException internal (reason: DestroyReason) =
    inherit NOnionException(sprintf "Circuit got destroyed, reason %A" reason)

type TimeoutErrorException internal () =
    inherit NOnionException("Time limit exceeded for operation")

type UnsuccessfulHttpRequestException internal (statusCode: string) =
    inherit NOnionException(sprintf
                                "Non-200 status code received, code: %s"
                                statusCode)

type UnsuccessfulIntroductionException internal (status: RelayIntroduceStatus) =
    inherit NOnionException(sprintf "Unsuccessful introduction: %A" status)

type NOnionSocketException
    internal
    (
        innerException: Net.Sockets.SocketException
    ) =
    inherit NOnionException
        (
            "Got socket exception during data transfer",
            innerException
        )
