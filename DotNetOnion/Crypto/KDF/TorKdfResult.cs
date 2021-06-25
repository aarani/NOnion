using System;
using System.Collections.Generic;
using System.Text;

namespace DotNetOnion.Crypto.KDF
{
    internal class TorKdfResult
    {
        public byte[] KeyHandshake { get; init; }
        public byte[] ForwardDigest { get; init; }
        public byte[] BackwardDigest { get; init; }
        public byte[] ForwardKey { get; init; }
        public byte[] BackwardKey { get; init; }
    }
}
