namespace NOnion.Utility

open System.Threading

type SemaphoreLocker () =
    //FIXME: Semaphores are not disposed correctly
    let semaphore = new SemaphoreSlim 1

    member __.RunAsyncWithSemaphore (func: unit -> Async<'T>) : Async<'T> =
        async {
            try
                do! semaphore.WaitAsync () |> Async.AwaitTask
                return! func ()
            finally
                semaphore.Release () |> ignore<int>
        }

    member __.RunSyncWithSemaphore (func: unit -> 'T) : 'T =
        try
            semaphore.Wait ()
            func ()
        finally
            semaphore.Release () |> ignore<int>
