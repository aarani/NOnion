using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using DotNetOnion.Crypto.KDF;

namespace DotNetOnion.KeyAgreements
{
    internal class FastKeyAgreement : IKeyAgreement
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
        public TorKdfResult CalculateKey(byte[] serverResponse)
        {
            byte[] K0 = new byte[serverResponse.Length + x.Length];
            Buffer.BlockCopy(x, 0, K0, 0, x.Length);
            Buffer.BlockCopy(serverResponse, 0, K0, x.Length, serverResponse.Length);

            return LegacyKdf.Compute(K0);
        }
    }
}
