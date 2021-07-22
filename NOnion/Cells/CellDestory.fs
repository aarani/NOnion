namespace NOnion.Cells

open System.IO

type CellDestroy =
    {
        Reason: byte
    }

    static member Deserialize (reader: BinaryReader) =
        {
            Reason = reader.ReadByte ()
        }
        :> ICell

    interface ICell with

        member __.Command = 4uy

        member self.Serialize writer =
            writer.Write self.Reason
