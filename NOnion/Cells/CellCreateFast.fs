namespace NOnion.Cells

open System.IO

open NOnion

type CellCreateFast = 
    {
        X: array<byte>
    }

    static member Deserialize (reader : BinaryReader) =
        let x = reader.ReadBytes Constants.HashLength
        { X = x } :> ICell

    interface ICell with
    
        member self.Command = 5uy

        member self.Serialize writer = 
            writer.Write self.X