using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;

namespace DotNetOnion.Cells
{
    public class CellNetInfo : Cell
    {
        public uint Time { get; set; }
        public ORAddress OtherAddress { get; set; }
        public ORAddress MyAddress { get; set; }

        public override byte Command => 0x07;

        public override void Deserialize(BinaryReader reader)
        {
            Time = reader.ReadUInt32BigEndian();
            OtherAddress = ReadORAddress(reader);
            MyAddress = ReadORAddress(reader);
        }

        private ORAddress ReadORAddress (BinaryReader reader)
        {
            return new ORAddress
            {
                Type = reader.ReadByte(),
                Value = reader.ReadBytes(reader.ReadByte())
            };
        }

        private void WriteORAddress(ORAddress address, BinaryWriter writer)
        {
            writer.Write(address.Type);
            writer.Write((byte)address.Value.Length);
            writer.Write(address.Value);
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.WriteBigEndian(Time);
            WriteORAddress(OtherAddress, writer);
            WriteORAddress(MyAddress, writer);
        }

        public class ORAddress
        {
            public byte Type { get; set; }
            public byte[] Value { get; set; }
        }

    }
}
