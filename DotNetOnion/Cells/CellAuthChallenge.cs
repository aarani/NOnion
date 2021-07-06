using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;

namespace DotNetOnion.Cells
{
    public class CellAuthChallenge : Cell
    {
        public byte[] Challenge { get; set; }
        public List<ushort> Methods { get; set; } = new List<ushort>();
        public override byte Command => 130;

        public override void Deserialize(BinaryReader reader)
        {
            Challenge = reader.ReadBytes(32);
            var len = reader.ReadUInt16BigEndian();
            for (int i = 0; i < len; i++)
            {
                Methods.Add(reader.ReadUInt16BigEndian());
            }
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Challenge);
            writer.WriteUInt16BigEndian((ushort)Methods.Count);
            foreach (var method in Methods)
            {
                writer.WriteUInt16BigEndian(method);
            }
        }
    }

}
