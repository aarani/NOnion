using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using NOnion.Cells;

namespace DotNetOnion.Cells
{
    public class CellDestroy : ICell
    {
        public byte Reason { get; set; }

        public byte Command => 0x04;

        public void Deserialize(BinaryReader reader)
        {
            Reason = reader.ReadByte();
        }

        public void Serialize(BinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
