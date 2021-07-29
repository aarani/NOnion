namespace NOnion.Crypto

open System

open NOnion.Crypto.Kdf

type TorCryptoState =
    {
        ForwardCipher: TorStreamCipher
        BackwardCipher: TorStreamCipher
        ForwardDigest: TorMessageDigest
        BackwardDigest: TorMessageDigest
    }

    static member FromKdfResult (kdfResult: KdfResult) : TorCryptoState =
        let fCipher = TorStreamCipher (kdfResult.ForwardKey, None)
        let bCipher = TorStreamCipher (kdfResult.BackwardKey, None)
        let fDigest = TorMessageDigest ()
        let bDigest = TorMessageDigest ()

        fDigest.Update kdfResult.ForwardDigest 0 kdfResult.ForwardDigest.Length

        bDigest.Update
            kdfResult.BackwardDigest
            0
            kdfResult.BackwardDigest.Length

        {
            ForwardCipher = fCipher
            BackwardCipher = bCipher
            ForwardDigest = fDigest
            BackwardDigest = bDigest
        }
