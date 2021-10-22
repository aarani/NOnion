namespace NOnion

open System
open System.Threading
open System.Threading.Tasks

module AsyncUtil =
    // Snippet from http://www.fssnip.net/hx/title/AsyncAwaitTask-with-timeouts
    let AwaitTaskWithTimeout (timeout: TimeSpan) (task: Task<'T>) =
        async {
            use cts = new CancellationTokenSource ()
            use timer = Task.Delay (timeout, cts.Token)
            let! completed = Async.AwaitTask <| Task.WhenAny (task, timer)

            if completed = (task :> Task) then
                cts.Cancel ()

                let! result = Async.AwaitTask task
                return result
            else
                return raise TimeoutErrorException
        }

    let AwaitNonGenericTaskWithTimeout (timeout: TimeSpan) (task: Task) =
        async {
            use cts = new CancellationTokenSource ()
            use timer = Task.Delay (timeout, cts.Token)
            let! completed = Async.AwaitTask <| Task.WhenAny (task, timer)

            if completed = task then
                cts.Cancel ()

                let! result = Async.AwaitTask task
                return result
            else
                return raise TimeoutErrorException
        }
