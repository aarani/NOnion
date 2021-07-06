using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;
using NOnion.Cells;

namespace DotNetOnion.Cells
{
    public class CellDestroy : Cell
    {
        public byte Reason { get; set; }

        public override byte Command => 0x04;

        public override void Deserialize(BinaryReader reader)
        {
            Reason = reader.ReadByte();
        }

        public override void Serialize(BinaryWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
