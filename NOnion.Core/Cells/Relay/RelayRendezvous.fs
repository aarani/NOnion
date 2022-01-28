namespace NOnion.Core.Cells.Relay

open System.IO

type RelayRendezvous =
    {
        Cookie: array<byte>
        HandshakeData: array<byte>
    }

    member self.ToBytes() =
        Array.concat [ self.Cookie; self.HandshakeData ]

    static member FromBytes(reader: BinaryReader) =
        {
            Cookie = Array.empty
            HandshakeData =
                (reader.BaseStream.Length - reader.BaseStream.Position)
                |> int
                |> reader.ReadBytes
        }
