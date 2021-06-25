using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DotNetOnion.Cells
{
    public abstract class Cell
    {
        public abstract byte Command { get; }

        public abstract void Deserialize(BinaryReader reader);
        public abstract void Serialize(BinaryWriter writer);
    }
}
