namespace NOnion.Utility

module SeqUtils =
    let TakeRandom count sequence =
        sequence |> Seq.sortBy(fun _ -> System.Guid.NewGuid()) |> Seq.take count
