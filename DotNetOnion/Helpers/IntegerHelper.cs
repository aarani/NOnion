using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace DotNetOnion.Helpers
{
    static internal class IntegerHelper
    {
        public static byte[] ToBigEndianByteArray(this ushort num)
        {
            var bytes = BitConverter.GetBytes(num);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            return bytes;
        }

        public static ushort ToUInt16BigEndian(byte[] bytes)
        {
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            return BitConverter.ToUInt16(bytes, 0);
        }

        public static byte[] ToBigEndianByteArray(this uint num)
        {
            var bytes = BitConverter.GetBytes(num);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            return bytes;
        }

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
