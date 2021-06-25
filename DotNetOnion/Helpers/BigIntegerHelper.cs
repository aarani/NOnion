using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace DotNetOnion.Helpers
{
    internal static class BigIntegerHelper
    {
        public static BigInteger FromBigEndianBytes(byte[] bytes)
        {
            var result = new byte[bytes.Length];
            Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
            Array.Reverse(result);
            return new BigInteger(result);
        }

        public static byte[] ToBigEndianBytes(this BigInteger num)
        {
            var result = num.ToByteArray();
            Array.Reverse(result);
            return result;
        }
    }
}
