namespace NOnion.Crypto

open Org.BouncyCastle.Crypto.Digests

open NOnion.Utility

module HiddenServicesCipher =
    let CalculateMacWithSHA3256 (key: array<byte>) (msg: array<byte>) =
        let data =
            let keyLenBytes =
                key.LongLength
                |> uint64
                |> IntegerSerialization.FromUInt64ToBigEndianByteArray

            Array.concat [ keyLenBytes; key; msg ]

        let digestEngine = Sha3Digest ()
        let output = Array.zeroCreate (digestEngine.GetDigestSize ())
        digestEngine.BlockUpdate (data, 0, data.Length)
        digestEngine.DoFinal (output, 0) |> ignore<int>

        output
