namespace NOnion

open System
open System.Runtime.ExceptionServices

module FSharpUtil =
    //Implementation copied from https://github.com/nblockchain/geewallet/blob/master/src/GWallet.Backend/FSharpUtil.fs
    let ReRaise(ex: Exception) : Exception =
        (ExceptionDispatchInfo.Capture ex).Throw()
        failwith "Should be unreachable"
        ex

    let rec public FindException<'T when 'T :> Exception>
        (ex: Exception)
        : Option<'T> =
        let rec findExInSeq(sq: seq<Exception>) =
            match Seq.tryHead sq with
            | Some head ->
                match FindException head with
                | Some ex -> Some ex
                | None -> findExInSeq <| Seq.tail sq
            | None -> None

        if isNull ex then
            None
        else
            match ex with
            | :? 'T as specificEx -> Some specificEx
            | :? AggregateException as aggEx ->
                findExInSeq aggEx.InnerExceptions
            | _ -> FindException<'T> ex.InnerException

    type private Either<'Val, 'Err when 'Err :> Exception> =
        | FailureResult of 'Err
        | SuccessfulValue of 'Val

    let WithTimeout (timeSpan: TimeSpan) (job: Async<'R>) : Async<'R> =
        async {
            let read =
                async {
                    let! value = job
                    return value |> SuccessfulValue |> Some
                }

            let delay =
                async {
                    let total = int timeSpan.TotalMilliseconds
                    do! Async.Sleep total
                    return FailureResult <| TimeoutException() |> Some
                }

            let! dummyOption = Async.Choice([ read; delay ])

            match dummyOption with
            | Some theResult ->
                match theResult with
                | SuccessfulValue r -> return r
                | FailureResult _ -> return raise <| TimeoutErrorException()
            | None ->
                // none of the jobs passed to Async.Choice returns None
                return failwith "unreachable"
        }
