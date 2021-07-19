namespace NOnion.Crypto.Kdf

open System.Security.Cryptography

open NOnion

module Kdf =
    let computeLegacyKdf (k0: array<byte>) : KdfResult =
        use sha1Engine = new SHA1Managed ()

        let rec innerCompute (i: byte) (state: array<byte>) =
            if state.Length > Constants.KdfLength then
                state
            else
                let hashResult =
                    sha1Engine.ComputeHash (Array.append k0 [| i |])

                innerCompute (i + 1uy) (Array.append state hashResult)

        let kdfBytes = innerCompute 0uy Array.empty

        // Offset = 0, Length = HashLength
        let keyHandshake = Array.take Constants.HashLength kdfBytes

        // Offset = HashLength, Length = HashLength
        let forwardDigest =
            Array.skip Constants.HashLength kdfBytes
            |> Array.take Constants.HashLength

        // Offset = 2 * HashLength, Length = HashLength
        let backwardDigest =
            Array.skip (2 * Constants.HashLength) kdfBytes
            |> Array.take Constants.HashLength

        // Offset = 3 * HashLength, Length = KeyLength
        let forwardKey =
            Array.skip (3 * Constants.HashLength) kdfBytes
            |> Array.take Constants.KeyLength

        // Offset = 3 * HashLength + KeyLength, Length = KeyLength
        let backwardKey =
            Array.skip (3 * Constants.HashLength + Constants.KeyLength) kdfBytes
            |> Array.take Constants.KeyLength

        {
            BackwardDigest = backwardDigest
            BackwardKey = backwardKey
            ForwardDigest = forwardDigest
            ForwardKey = forwardKey
            KeyHandshake = keyHandshake
        }
