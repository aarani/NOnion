namespace NOnion.Crypto

open System

open NOnion.Crypto.Kdf

type TorCryptoState =
    {
        ForwardCipher: TorStreamCipher
        BackwardCipher: TorStreamCipher
        ForwardDigest: TorMessageDigest
        BackwardDigest: TorMessageDigest
        KeyHandshake: array<byte>
    }

    static member FromKdfResult
        (kdfResult: KdfResult)
        (reverse: bool)
        : TorCryptoState =
        let forwardCipher = TorStreamCipher(kdfResult.ForwardKey, None)
        let backwardCipher = TorStreamCipher(kdfResult.BackwardKey, None)
        let forwardDigest = TorMessageDigest kdfResult.IsHSV3
        let backwardDigest = TorMessageDigest kdfResult.IsHSV3

        forwardDigest.Update
            kdfResult.ForwardDigest
            0
            kdfResult.ForwardDigest.Length

        backwardDigest.Update
            kdfResult.BackwardDigest
            0
            kdfResult.BackwardDigest.Length

        if reverse then
            {
                ForwardCipher = backwardCipher
                BackwardCipher = forwardCipher
                ForwardDigest = backwardDigest
                BackwardDigest = forwardDigest
                KeyHandshake = kdfResult.KeyHandshake
            }
        else
            {
                ForwardCipher = forwardCipher
                BackwardCipher = backwardCipher
                ForwardDigest = forwardDigest
                BackwardDigest = backwardDigest
                KeyHandshake = kdfResult.KeyHandshake
            }
