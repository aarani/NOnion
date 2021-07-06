using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DotNetOnion.Helpers
{
    internal static class BinaryIOHelper
    {
        public static void WriteUInt16BigEndian(this BinaryWriter writer, ushort num)
        {
            writer.Write(num.ToBigEndianByteArray());
        }

        public static void WriteUInt32BigEndian(this BinaryWriter writer, uint num)
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
