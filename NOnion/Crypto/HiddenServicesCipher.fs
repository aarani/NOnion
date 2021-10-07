namespace NOnion.Crypto

open System.Text

open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Signers
open Chaos.NaCl

open NOnion
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

    let CalculateBlindingFactor
        (periodNumber: uint64, periodLength: uint64)
        (publicKey: array<byte>)
        =
        let nonce =
            Array.concat
                [
                    "key-blind" |> Encoding.ASCII.GetBytes
                    periodNumber
                    |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                    periodLength
                    |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                ]

        let digestEngine = Sha3Digest ()
        let output = Array.zeroCreate (digestEngine.GetDigestSize ())

        digestEngine.BlockUpdate (
            Constants.HiddenServiceBlindString,
            0,
            Constants.HiddenServiceBlindString.Length
        )

        digestEngine.BlockUpdate (publicKey, 0, publicKey.Length)

        digestEngine.BlockUpdate (
            Constants.Ed25519BasePointString,
            0,
            Constants.Ed25519BasePointString.Length
        )

        digestEngine.BlockUpdate (nonce, 0, nonce.Length)
        digestEngine.DoFinal (output, 0) |> ignore<int>

        //CLAMPING
        output.[0] <- output.[0] &&& 248uy
        output.[31] <- output.[31] &&& 63uy
        output.[31] <- output.[31] ||| 64uy

        output

    let CalculateBlindedPublicKey
        (blindingFactor: array<byte>)
        (publicKey: array<byte>)
        =

        blindingFactor.[0] <- blindingFactor.[0] &&& 248uy
        blindingFactor.[31] <- blindingFactor.[31] &&& 63uy
        blindingFactor.[31] <- blindingFactor.[31] ||| 64uy

        let output = Array.zeroCreate 32

        match Ed25519.CalculateBlindedPublicKey (publicKey, blindingFactor) with
        | true, output -> output
        | false, _ -> failwith "can't calculate blinded public key"
