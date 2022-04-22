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
        let fCipher = TorStreamCipher(kdfResult.ForwardKey, None)
        let bCipher = TorStreamCipher(kdfResult.BackwardKey, None)
        let fDigest = TorMessageDigest(kdfResult.IsHSV3)
        let bDigest = TorMessageDigest(kdfResult.IsHSV3)

        fDigest.Update kdfResult.ForwardDigest 0 kdfResult.ForwardDigest.Length

        bDigest.Update
            kdfResult.BackwardDigest
            0
            kdfResult.BackwardDigest.Length

        if reverse then
            {
                ForwardCipher = bCipher
                BackwardCipher = fCipher
                ForwardDigest = bDigest
                BackwardDigest = fDigest
                KeyHandshake = kdfResult.KeyHandshake
            }
        else
            {
                ForwardCipher = fCipher
                BackwardCipher = bCipher
                ForwardDigest = fDigest
                BackwardDigest = bDigest
                KeyHandshake = kdfResult.KeyHandshake
            }
