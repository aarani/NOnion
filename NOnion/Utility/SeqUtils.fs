namespace NOnion.Utility

module SeqUtils =
    // Helper function copied from https://stackoverflow.com/a/21615676
    let Chunk n xs =
        xs
        |> Seq.mapi (fun i x -> i / n, x)
        |> Seq.groupBy fst
        |> Seq.map (fun (_, g) -> Seq.map snd g)

    let TakeRandom n xs =
        xs |> Seq.sortBy (fun _ -> System.Guid.NewGuid ()) |> Seq.take n
