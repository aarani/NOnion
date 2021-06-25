using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;

namespace DotNetOnion.Cells
{
    public class CellCreatedFast : Cell
    {
        public override byte Command => 0x06;

        public byte[] Y { get; set; }
        public byte[] DerivativeKeyData { get; set; }

        public override void Deserialize(BinaryReader reader)
        {
            Y = reader.ReadBytes(Constants.HashLength);
            DerivativeKeyData = reader.ReadBytes(Constants.HashLength);
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Y);
            writer.Write(DerivativeKeyData); 
        }
    }
}
