using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace DotNetOnion.Crypto
{
    /*
     * This class wraps bouncycastle's digest class for use in relay cell digest calculation.
     * We have to use bouncycastle's SHA instead of .NET's because .NET version have no option
     * to keep the state (for a running digest) but you can clone the BCL version before resetting the state.
     */
    public class TorMessageDigest
    {
        public const int TOR_DIGEST_SIZE = 20;
        public const int TOR_DIGEST256_SIZE = 32;

        private readonly GeneralDigest digestInstance;
        private readonly bool isSha256;
        private readonly int hashSize;
        public TorMessageDigest(bool isSha256 = false)
        {
            this.isSha256 = isSha256;
            hashSize = isSha256 ?
                TOR_DIGEST256_SIZE : TOR_DIGEST_SIZE;
            digestInstance =
                createDigestInstance();
        }

        private GeneralDigest createDigestInstance(GeneralDigest oldDigest = null)
        {
            if (isSha256)
                return
                    oldDigest switch
                    {
                        null => new Sha256Digest(),
                        _ => new Sha256Digest((Sha256Digest)oldDigest),
                    };
            else
                return
                    oldDigest switch
                    {
                        null => new Sha1Digest(),
                        _ => new Sha1Digest((Sha1Digest)oldDigest),
                    };
        }

        public bool IsDigest256()
        {
            return isSha256;
        }

        /**
         * Return the digest value of all data processed up until this point.
         * @return The digest value as an array of <code>TOR_DIGEST_SIZE<code> or <code>TOR_DIGEST256_SIZE</code> bytes.
         */
        public byte[] GetDigestBytes()
        {
            var hash = new byte[hashSize];
            var clone = createDigestInstance(digestInstance);
            clone.DoFinal(hash, 0);
            return hash;
        }

        /**
	     * Return what the digest for the current running hash would be IF we
	     * added <code>data</code>, but don't really add the data to the digest
	     * calculation.
	     */
        public byte[] PeekDigest(byte[] data, int offset, int length)
        {
            var hash = new byte[hashSize];
            var clone = createDigestInstance(digestInstance);
            clone.BlockUpdate(data, offset, length);
            clone.DoFinal(hash, 0);
            return hash;
        }

        /**
	     * Add the entire contents of the byte array <code>input</code> to the current digest calculation.
	     * 
	     * @param input An array of input bytes to process.
	     */
        public void Update(byte[] input)
        {
            Update(input, 0, input.Length);
        }

        /**
         * Add <code>length</code> bytes of the contents of the byte array <code>input</code> beginning at 
         * <code>offset</code> into the array to the current digest calculation.
         * 
         * @param input An array of input bytes to process.
         * @param offset The offset into the <code>input</code> array to begin processing.
         * @param length A count of how many bytes of the <code>input</code> array to process.
         */
        public void Update(byte[] input, int offset, int length)
        {
            digestInstance.BlockUpdate(input, offset, length);
        }

    }
}
