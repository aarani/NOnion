using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;

namespace DotNetOnion.Cells
{
    public class CellPadding : Cell
    {
        public override byte Command => 0x00;

        public override void Deserialize(BinaryReader reader)
        {
            _ = reader.ReadByte();
            _ = reader.ReadByte();
            _ = reader.ReadUInt16BigEndian();
            _ = reader.ReadUInt16BigEndian();
        }

        public override void Serialize(BinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
