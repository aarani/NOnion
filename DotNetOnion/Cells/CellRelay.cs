using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;

namespace DotNetOnion.Cells
{
    public class CellRelay : Cell
    {
        public RelayCommand RelayCommand { get; set; }
        public ushort Recognized { get; set; }
        public ushort StreamId { get; set; }
        public byte[] Digest { get; set; }
        public byte[] Data { get; set; }

        public override byte Command => 0x03;

        public override void Deserialize(BinaryReader reader)
        {
            RelayCommand = (RelayCommand)reader.ReadByte();
            Recognized = reader.ReadUInt16BigEndian();
            StreamId = reader.ReadUInt16BigEndian();
            Digest = reader.ReadBytes(4);
            Data = reader.ReadBytes(reader.ReadUInt16BigEndian());
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write((byte)RelayCommand);
            writer.WriteBigEndian(Recognized);
            writer.WriteBigEndian(StreamId);
            writer.Write(Digest);
            writer.WriteBigEndian((ushort)Data.Length);
        }
    }

    public enum RelayCommand
    {
        BEGIN = 1,
        DATA = 2,
        END = 3,
        CONNECTED = 4,
        SENDME = 5,
        EXTEND = 6,
        EXTENDED = 7,
        TRUNCATE = 8,
        TRUNCATED = 9,
        DROP = 10,
        RESOLVE = 11,
        RESOLVED = 12,
        BEGIN_DIR = 13,
        EXTEND2 = 14,
        EXTENDED2 = 15,
    }
}
