using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NOnion.Tests.Utility
{
    internal static class TaskUtils
    {
        internal static Task WhenAllFailFast(params Task[] tasks)
        {
            if (tasks == null) throw new ArgumentNullException(nameof(tasks));

            var cts = new CancellationTokenSource();
            Task failedTask = null;
            var continuationAction = new Action<Task>(task =>
            {
                if (!task.IsCompletedSuccessfully)
                    if (Interlocked.CompareExchange(ref failedTask, task, null) == null)
                        cts.Cancel();
            });
            var continuations = tasks.Select(task => task.ContinueWith(continuationAction,
                cts.Token, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default));

            return Task.WhenAll(continuations).ContinueWith(_ =>
            {
                cts.Dispose();
                if (failedTask != null) return Task.WhenAll(failedTask);
                // At this point all the tasks are completed successfully
                return Task.WhenAll(tasks);
            }, TaskScheduler.Default).Unwrap();
        }
    }
}
