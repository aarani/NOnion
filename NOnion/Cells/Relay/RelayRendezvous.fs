namespace NOnion.Cells.Relay

open System.IO

type RelayRendezvous =
    {
        Cookie: array<byte>
        HandshakeData: array<byte>
    }

    member self.ToBytes () =
        Array.concat [ self.Cookie; self.HandshakeData ]

    static member FromBytes (reader: BinaryReader) =
        {
            Cookie = Array.zeroCreate 0
            HandshakeData =
                (reader.BaseStream.Length - reader.BaseStream.Position)
                |> int
                |> reader.ReadBytes
        }
