namespace NOnion.Utility

open System

open NOnion

module DateTimeUtils =
    let internal GetTimeSpanSinceEpoch(dt: DateTime) =
        dt - Constants.UnixEpoch

    let internal ToUnixTimestamp(dt: DateTime) =
        (GetTimeSpanSinceEpoch dt).TotalSeconds |> uint

    let internal FromUnixTimestamp(num: uint) =
        num |> float |> Constants.UnixEpoch.AddSeconds
