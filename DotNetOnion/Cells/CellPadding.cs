using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using NOnion.Cells;
using NOnion.Utility;

namespace DotNetOnion.Cells
{
    public class CellPadding : ICell
    {
        public byte Command => 0x00;

        public void Deserialize(BinaryReader reader)
        {
            _ = reader.ReadByte();
            _ = reader.ReadByte();
            _ = reader.Read();
            _ = BinaryIO.ReadBigEndianUInt16(reader);
        }

        public void Serialize(BinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
