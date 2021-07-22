namespace NOnion.Cells

open System.IO

open NOnion

type CellPadding =
    {
        Bytes: array<byte>
    }

    static member Deserialize (reader: BinaryReader) =
        {
            Bytes = reader.ReadBytes Constants.FixedPayloadLength
        }
        :> ICell

    interface ICell with

        member __.Command = 0uy

        member self.Serialize writer =
            writer.Write self.Bytes
