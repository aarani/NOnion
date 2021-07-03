using System;
using System.Collections.Generic;
using System.Text;

namespace DotNetOnion.Crypto.KDF
{
    public class TorKdfResult
    {
        public byte[] KeyHandshake { get; set; }
        public byte[] ForwardDigest { get; set; }
        public byte[] BackwardDigest { get; set; }
        public byte[] ForwardKey { get; set; }
        public byte[] BackwardKey { get; set; }
    }
}
