using System;
using DotNetOnion.Crypto;
using DotNetOnion.Crypto.KDF;

namespace DotNetOnion
{
    internal class TorCryptoState
    {
        public TorStreamCipher forwardCipher { get; }
        public TorStreamCipher backwardCipher { get; }
        public TorMessageDigest forwardDigest { get; }
        public TorMessageDigest backwardDigest { get; }

        private TorCryptoState(TorStreamCipher forwardCipher, TorStreamCipher backwardCipher, TorMessageDigest forwardDigest, TorMessageDigest backwardDigest)
        {
            this.forwardCipher = forwardCipher;
            this.backwardCipher = backwardCipher;
            this.forwardDigest = forwardDigest;
            this.backwardDigest = backwardDigest;
        }
        internal static TorCryptoState CreateFromKdfResult(TorKdfResult kdfResult)
        {
            TorStreamCipher fCipher = new(kdfResult.ForwardKey);
            TorStreamCipher bCipher = new(kdfResult.BackwardKey);

            TorMessageDigest fDigest = new();
            TorMessageDigest bDigest = new();

            fDigest.Update(kdfResult.ForwardDigest);
            bDigest.Update(kdfResult.BackwardDigest);

            return new TorCryptoState(fCipher, bCipher, fDigest, bDigest);
        }
    }
}