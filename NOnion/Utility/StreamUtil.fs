namespace NOnion.Utility

open System
open System.IO

module StreamUtil =
    let ReadFixedSize (stream: Stream) (count: int) =
        async {
            let! ct = Async.CancellationToken

            try
                let rec readUntilBufferIsFull buffer offset =
                    async {
                        if ct.IsCancellationRequested || not stream.CanRead then
                            return None
                        else
                            let! filledBytes =
                                stream.ReadAsync(
                                    buffer,
                                    offset,
                                    count - offset,
                                    ct
                                )
                                |> Async.AwaitTask

                            if filledBytes = 0 then
                                return None
                            elif filledBytes + offset = count then
                                return Some buffer
                            else
                                return!
                                    readUntilBufferIsFull
                                        buffer
                                        (offset + filledBytes)
                    }

                let buffer = Array.zeroCreate count
                return! readUntilBufferIsFull buffer 0
            with
            | :? ObjectDisposedException
            | :? OperationCanceledException -> return None
        }

    let Write (stream: Stream) (buffer: array<byte>) =
        async {
            let! ct = Async.CancellationToken

            return!
                stream.WriteAsync(buffer, 0, buffer.Length, ct)
                |> Async.AwaitTask
        }
