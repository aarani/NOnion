using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DotNetOnion.Cells
{
    public class CellRelayEncrypted : Cell
    {
        public byte[] EncryptedData { get; set; }

        public override byte Command => 0x03;

        public override void Deserialize(BinaryReader reader)
        {
            EncryptedData = reader.ReadBytes(Constants.FixedPayloadLength);
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(EncryptedData);
        }
    }
}
