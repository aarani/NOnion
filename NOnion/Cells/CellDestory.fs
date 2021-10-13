namespace NOnion.Cells

open System.IO

open NOnion

type CellDestroy =
    {
        Reason: DestroyReason
    }

    static member Deserialize (reader: BinaryReader) =
        {
            Reason =
                reader.ReadByte ()
                |> LanguagePrimitives.EnumOfValue<byte, DestroyReason>
        }
        :> ICell

    interface ICell with

        member __.Command = 4uy

        member self.Serialize writer =
            writer.Write (self.Reason |> byte)
