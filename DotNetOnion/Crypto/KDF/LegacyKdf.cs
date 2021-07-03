using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DotNetOnion.Crypto.KDF
{
    public static class LegacyKdf
    {
        public static TorKdfResult Compute(byte[] k0)
        {
            List<byte> kdfResult = new List<byte>(2 * Constants.KeyLength + 3 * Constants.HashLength);
            using var sha1Engine = new SHA1Managed();

            byte i = 0;

            while (kdfResult.Count < 2 * Constants.KeyLength + 3 * Constants.HashLength)
            {
                byte[] toHash = new byte[k0.Length + 1];
                Buffer.BlockCopy(k0, 0, toHash, 0, k0.Length);
                toHash[toHash.Length - 1] = i++;

                kdfResult.AddRange(sha1Engine.ComputeHash(toHash));
            }

            return new TorKdfResult
            {
                KeyHandshake = kdfResult.Take(Constants.HashLength).ToArray(),
                ForwardDigest = kdfResult.Skip(Constants.HashLength).Take(Constants.HashLength).ToArray(),
                BackwardDigest = kdfResult.Skip(2 * Constants.HashLength).Take(Constants.HashLength).ToArray(),
                ForwardKey = kdfResult.Skip(3 * Constants.HashLength).Take(Constants.KeyLength).ToArray(),
                BackwardKey = kdfResult.Skip(3 * Constants.HashLength + Constants.KeyLength).Take(Constants.KeyLength).ToArray(),
            };
        }
    }
}
