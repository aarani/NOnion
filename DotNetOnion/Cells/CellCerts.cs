using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetOnion.Helpers;

namespace DotNetOnion.Cells
{
    public class CellCerts : Cell
    {
        public List<Cert> Certs { get; set; } = new List<Cert>();
        public override byte Command => 129;

        public override void Deserialize(BinaryReader reader)
        {
            int certCount = reader.ReadByte();

            for (int i = 0; i < certCount; i++)
            {
                Certs.Add(new Cert
                {
                    Type = reader.ReadByte(),
                    Certificate = reader.ReadBytes(reader.ReadUInt16BigEndian())
                });
            }
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write((byte)Certs.Count);

            foreach (var cert in Certs)
            {
                writer.Write(cert.Type);
                writer.WriteBigEndian((ushort)cert.Certificate.Length);
                writer.Write(cert.Certificate);
            }
        }
    }

    public class Cert
    {
        public byte Type { get; set; }
        public byte[] Certificate { get; set; }
    }
}
