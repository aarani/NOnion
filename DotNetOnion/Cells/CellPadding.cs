using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;
using NOnion.Cells;

namespace DotNetOnion.Cells
{
    public class CellPadding : ICell
    {
        public byte Command => 0x00;

        public void Deserialize(BinaryReader reader)
        {
            _ = reader.ReadByte();
            _ = reader.ReadByte();
            _ = reader.ReadUInt16BigEndian();
            _ = reader.ReadUInt16BigEndian();
        }

        public void Serialize(BinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
