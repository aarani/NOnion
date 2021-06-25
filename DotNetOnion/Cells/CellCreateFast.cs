using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;

namespace DotNetOnion.Cells
{
    public class CellCreateFast : Cell
    {
        public override byte Command => 0x05;

        public byte[] X { get; set; }

        public override void Deserialize(BinaryReader reader)
        {
            X = reader.ReadBytes(Constants.HashLength);
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(X);
        }
    }
}
