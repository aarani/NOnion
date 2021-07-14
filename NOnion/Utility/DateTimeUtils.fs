namespace NOnion.Utility

open System

module DateTimeUtils =
    let ToUnixTimestamp (dt: DateTime) =
        let timeSpan = dt - DateTime (1970, 1, 1)
        timeSpan.TotalSeconds |> uint
