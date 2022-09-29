﻿namespace NOnion

open System

type NOnionException =
    inherit Exception

    new(msg: string) = { inherit Exception(msg) }

    new(msg: string, innerException: Exception) =
        { inherit Exception(msg, innerException) }

type GuardConnectionFailedException =
    inherit NOnionException

    new(innerException: Exception) =
        { inherit NOnionException("Connecting to guard node failed",
                                  innerException) }

    new(message: string) =
        { inherit NOnionException("Connecting to guard node failed: " + message) }


type CircuitTruncatedException(reason: DestroyReason) =
    inherit NOnionException(sprintf "Circuit got truncated, reason %A" reason)

type CircuitDestroyedException(reason: DestroyReason) =
    inherit NOnionException(sprintf "Circuit got destroyed, reason %A" reason)

type TimeoutErrorException() =
    inherit NOnionException("Time limit exceeded for operation")

type UnsuccessfulHttpRequestException(statusCode: string) =
    inherit NOnionException(sprintf
                                "Non-200 status code received, code: %s"
                                statusCode)

type UnsuccessfulIntroductionException(status: RelayIntroduceStatus) =
    inherit NOnionException(sprintf "Unsuccessful introduction: %A" status)
