using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;

namespace DotNetOnion.Cells
{
    public class CellVersions : Cell
    {
        public List<ushort> Versions { get; set; } = new List<ushort>();
        public override byte Command => 0x07;

        public override void Deserialize(BinaryReader reader)
        {
            if (reader.BaseStream.Length % 2 != 0)
                throw new Exception("Version packet payload is invalid, payload length should be divisable by 2");

            while (reader.BaseStream.Length != reader.BaseStream.Position)
            {
                Versions.Add(reader.ReadUInt16BigEndian());
            }
        }

        public override void Serialize(BinaryWriter writer)
        {
            foreach (var version in Versions)
            {
                writer.WriteBigEndian(version);
            }
        }
    }
}
