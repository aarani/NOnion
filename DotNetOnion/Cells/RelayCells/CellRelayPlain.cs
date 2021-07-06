using System;
using System.IO;
using System.Security.Cryptography;
using DotNetOnion.Enums;
using DotNetOnion.Helpers;

namespace DotNetOnion.Cells
{
    public class CellRelayPlain
    {
        public RelayCommand RelayCommand { get; set; }
        public ushort Recognized { get; set; }
        public ushort StreamId { get; set; }
        public byte[] Digest { get; set; }
        public byte[] Data { get; set; }
        private byte[] padding;

        private void InitializePadding()
        {
            if (padding == null)
            {
                padding = new byte[Constants.FixedPayloadLength - 11 - Data.Length];
                RandomNumberGenerator.Create().GetNonZeroBytes(padding);
                Array.Clear(padding, 0, Math.Min(padding.Length, 4));
            }
        }

        public void FromBytes(byte[] bytes)
        {
            using MemoryStream memStream = new(bytes);
            using BinaryReader reader = new(memStream);
            RelayCommand = (RelayCommand)reader.ReadByte();
            Recognized = reader.ReadUInt16BigEndian();
            StreamId = reader.ReadUInt16BigEndian();
            Digest = reader.ReadBytes(4);
            Data = reader.ReadBytes(reader.ReadUInt16BigEndian());
            padding = reader.ReadBytes(Constants.FixedPayloadLength - 11 - Data.Length);
        }

        public byte[] ToBytes(bool emptyDigest = false)
        {
            InitializePadding();
            using MemoryStream memStream = new(Constants.FixedPayloadLength);
            using BinaryWriter writer = new(memStream);
            writer.Write((byte)RelayCommand);
            writer.WriteUInt16BigEndian(Recognized);
            writer.WriteUInt16BigEndian(StreamId);
            writer.Write(emptyDigest ? new byte[4] : Digest);
            writer.WriteUInt16BigEndian((ushort)Data.Length);
            writer.Write(Data);
            writer.Write(padding);
            return memStream.ToArray();
        }
    }
}
