namespace NOnion.Crypto.Kdf

open System.Security.Cryptography
open System.Text

open Org.BouncyCastle.Crypto.Digests
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters


open NOnion
open NOnion.Crypto

module Kdf =
    let ComputeLegacyKdf(k0: array<byte>) : KdfResult =
        use sha1Engine = new SHA1Managed()

        let rec innerCompute (i: byte) (state: array<byte>) =
            if state.Length > Constants.KdfLength then
                state
            else
                let hashResult = sha1Engine.ComputeHash(Array.append k0 [| i |])

                innerCompute(i + 1uy) (Array.append state hashResult)

        let kdfBytes = innerCompute 0uy Array.empty

        // Offset = 0, Length = HashLength
        let keyHandshake = Array.take Constants.HashLength kdfBytes

        // Offset = HashLength, Length = HashLength
        let forwardDigest =
            Array.skip Constants.HashLength kdfBytes
            |> Array.take Constants.HashLength

        // Offset = 2 * HashLength, Length = HashLength
        let backwardDigest =
            Array.skip(2 * Constants.HashLength) kdfBytes
            |> Array.take Constants.HashLength

        // Offset = 3 * HashLength, Length = KeyLength
        let forwardKey =
            Array.skip(3 * Constants.HashLength) kdfBytes
            |> Array.take Constants.KeyLength

        // Offset = 3 * HashLength + KeyLength, Length = KeyLength
        let backwardKey =
            Array.skip(3 * Constants.HashLength + Constants.KeyLength) kdfBytes
            |> Array.take Constants.KeyLength

        {
            BackwardDigest = backwardDigest
            BackwardKey = backwardKey
            ForwardDigest = forwardDigest
            ForwardKey = forwardKey
            KeyHandshake = keyHandshake
        }

    let ComputeRfc5869Kdf(ikm: array<byte>) : KdfResult =
        let kdfBytes = Array.zeroCreate Constants.KdfLength

        let hash = Sha256Digest()

        let parameters =
            HkdfParameters(ikm, Constants.NTorTKey, Constants.NTorMExpand)

        let hkdf = HkdfBytesGenerator hash
        hkdf.Init parameters
        hkdf.GenerateBytes(kdfBytes, 0, Constants.KdfLength) |> ignore<int>

        // Offset = 0, Length = HashLength
        let forwardDigest =
            Array.skip 0 kdfBytes |> Array.take Constants.HashLength

        // Offset = HashLength, Length = HashLength
        let backwardDigest =
            Array.skip Constants.HashLength kdfBytes
            |> Array.take Constants.HashLength

        // Offset = 2 * HashLength, Length = KeyLength
        let forwardKey =
            Array.skip(2 * Constants.HashLength) kdfBytes
            |> Array.take Constants.KeyLength

        // Offset = 2 * HashLength + KeyLength, Length = KeyLength
        let backwardKey =
            Array.skip(2 * Constants.HashLength + Constants.KeyLength) kdfBytes
            |> Array.take Constants.KeyLength

        // Offset = 2 * HashLength + 2 * KeyLength, Length = HashLength
        let keyHandshake =
            Array.skip
                (2 * Constants.HashLength + 2 * Constants.KeyLength)
                kdfBytes
            |> Array.take Constants.HashLength

        {
            BackwardDigest = backwardDigest
            BackwardKey = backwardKey
            ForwardDigest = forwardDigest
            ForwardKey = forwardKey
            KeyHandshake = keyHandshake
        }

    let ComputeHSKdf(ntorKeySeed: array<byte>) : KdfResult =
        let kdfBytes =
            Array.concat
                [
                    ntorKeySeed
                    Constants.HiddenServiceNTor.MExpand
                ]
            |> HiddenServicesCipher.CalculateShake256(
                2 * Constants.HashLength + 2 * Constants.KeyS256Length
            )

        // Offset = 0, Length = HashLength
        let forwardDigest =
            Array.skip 0 kdfBytes |> Array.take Constants.HashLength

        // Offset = HashLength, Length = HashLength
        let backwardDigest =
            Array.skip Constants.HashLength kdfBytes
            |> Array.take Constants.HashLength

        // Offset = 2 * HashLength, Length = KeyS256Length
        let forwardKey =
            Array.skip(2 * Constants.HashLength) kdfBytes
            |> Array.take Constants.KeyS256Length

        // Offset = 2 * HashLength + KeyS256Length, Length = KeyS256Length
        let backwardKey =
            Array.skip
                (2 * Constants.HashLength + Constants.KeyS256Length)
                kdfBytes
            |> Array.take Constants.KeyS256Length

        {
            BackwardDigest = backwardDigest
            BackwardKey = backwardKey
            ForwardDigest = forwardDigest
            ForwardKey = forwardKey
            KeyHandshake = Array.empty
        }
