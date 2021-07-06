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
        public List<ORAddress> MyAddresses { get; set; } = new List<ORAddress>();

        public override byte Command => 0x08;

        public override void Deserialize(BinaryReader reader)
        {
            Time = reader.ReadUInt32BigEndian();
            OtherAddress = ReadORAddress(reader);
            int myAddressCount = reader.ReadByte();
            for (int i = 0; i < myAddressCount; i++)
            {
                MyAddresses.Add(ReadORAddress(reader));
            }
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
            writer.WriteUInt32BigEndian(Time);
            WriteORAddress(OtherAddress, writer);
            writer.Write((byte)MyAddresses.Count);
            foreach (var address in MyAddresses)
                WriteORAddress(address, writer);
        }

        public class ORAddress
        {
            public byte Type { get; set; }
            public byte[] Value { get; set; }
        }

    }
}
