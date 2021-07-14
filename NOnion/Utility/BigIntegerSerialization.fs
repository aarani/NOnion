namespace NOnion.Utility

open System.Numerics

module BigIntegerSerialization =
    let FromBigEndianBytes (data: array<byte>) =
        data |> Array.rev |> BigInteger

    let ToBigEndianBytes (num: BigInteger) =
        num.ToByteArray () |> Array.rev
