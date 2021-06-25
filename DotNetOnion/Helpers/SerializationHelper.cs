using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DotNetOnion.Helpers
{
    public static class SerializationHelper
    {
        public static byte[] ToBigEndianByteArray(this ushort num)
        {
            var bytes = BitConverter.GetBytes(num);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            return bytes;
        }

        public static byte[] ToBigEndianByteArray(this uint num)
        {
            var bytes = BitConverter.GetBytes(num);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            return bytes;
        }

        public static void WriteBigEndian(this BinaryWriter writer, ushort num)
        {
            writer.Write(num.ToBigEndianByteArray());
        }
        public static void WriteBigEndian(this BinaryWriter writer, uint num)
        {
            writer.Write(num.ToBigEndianByteArray());
        }

        public static ushort ReadUInt16BigEndian(this BinaryReader reader)
        {
            var bytes = reader.ReadBytes(2);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return BitConverter.ToUInt16(bytes, 0);
        }

        public static uint ReadUInt32BigEndian(this BinaryReader reader)
        {
            var bytes = reader.ReadBytes(4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }
    }
}
