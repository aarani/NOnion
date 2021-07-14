using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using NOnion.Crypto.Kdf;

namespace DotNetOnion.KeyAgreements
{
    public class FastKeyAgreement : IKeyAgreement
    {
        private readonly byte[] x = new byte[Constants.HashLength];

        public FastKeyAgreement()
        {
            RandomNumberGenerator.Create().GetNonZeroBytes(x);
        }
        
        public byte[] CreateClientMaterial()
        {
            return x;
        }
        public KdfResult CalculateKey(byte[] serverResponse)
        {
            byte[] K0 = new byte[serverResponse.Length + x.Length];
            Buffer.BlockCopy(x, 0, K0, 0, x.Length);
            Buffer.BlockCopy(serverResponse, 0, K0, x.Length, serverResponse.Length);

            return Kdf.computeLegacyKdf(K0);
        }
    }
}
