using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
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
        public byte[] Padding { get; set; }

        public override byte Command => 0x03;

        private void InitializePadding()
        {
            if (Padding == null)
            {
                Padding = new byte[Constants.FixedPayloadLength - 11 - Data.Length];
                RandomNumberGenerator.Create().GetNonZeroBytes(Padding);
                Array.Clear(Padding, 0, Math.Min(Padding.Length, 4));
            }
        }

        public override void Deserialize(BinaryReader reader)
        {
            RelayCommand = (RelayCommand)reader.ReadByte();
            Recognized = reader.ReadUInt16BigEndian();
            StreamId = reader.ReadUInt16BigEndian();
            Digest = reader.ReadBytes(4);
            Data = reader.ReadBytes(reader.ReadUInt16BigEndian());
            Padding = reader.ReadBytes(Constants.FixedPayloadLength - 11 - Data.Length);
        }

        public override void Serialize(BinaryWriter writer)
        {
            InitializePadding();
            writer.Write((byte)RelayCommand);
            writer.WriteBigEndian(Recognized);
            writer.WriteBigEndian(StreamId);
            writer.Write(Digest);
            writer.WriteBigEndian((ushort)Data.Length);
            writer.Write(Data);
            writer.Write(Padding);
        }

        public bool IsRecognized()
        {
            return Array.TrueForAll(Digest, b => b == 0x00);
        }

        public void SerializeForDigest(BinaryWriter writer)
        {
            InitializePadding();
            writer.Write((byte)RelayCommand);
            writer.WriteBigEndian(Recognized);
            writer.WriteBigEndian(StreamId);
            writer.Write(new byte[4]);
            writer.WriteBigEndian((ushort)Data.Length);
            writer.Write(Padding);
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
