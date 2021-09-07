namespace NOnion.Crypto

open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Signers

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

    let SignWithED25519
        (privateKey: Ed25519PrivateKeyParameters)
        (data: array<byte>)
        =
        let signer = Ed25519Signer ()
        signer.Init (true, privateKey)
        signer.BlockUpdate (data, 0, data.Length)
        signer.GenerateSignature ()
