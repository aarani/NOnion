namespace NOnion.Utility

open System

module DateTimeUtils =
    let internal GetTimeSpanSinceEpoch(dt: DateTime) =
        dt - DateTime(1970, 1, 1)

    let internal ToUnixTimestamp(dt: DateTime) =
        (GetTimeSpanSinceEpoch dt).TotalSeconds |> uint

    let internal FromUnixTimestamp(num: uint) =
        DateTime(1970, 1, 1).AddSeconds (num |> float)