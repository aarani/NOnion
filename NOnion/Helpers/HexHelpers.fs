namespace NOnion.Helpers

open System

module HexHelpers =
    let ByteArrayToHex (bytes: array<byte>) : string =
        bytes
        |> Array.map (fun (x: byte) -> System.String.Format ("{0:X2}", x))
        |> String.concat String.Empty

    let HexToByteArray (hex: string) : array<byte> =
        if hex.Length % 2 <> 0 then
            invalidArg "hex" "hex.Length is not even"

        let bytes = Array.create (hex.Length / 2) 0uy

        let mutable i = 0

        while i < bytes.Length do
            bytes.[i] <- Convert.ToByte (hex.Substring (i * 2, 2), 16)
            i <- i + 1

        bytes
