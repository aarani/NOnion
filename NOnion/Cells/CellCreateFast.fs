namespace NOnion.Cells

open System.IO

open NOnion
open NOnion.Extensions.BinaryIOExtensions

type CellCreateFast (x: array<byte>) =

    member self.X = x
    
    static member Deserialize (reader : BinaryReader) =
        let x = reader.ReadBytes Constants.HashLength
        CellCreateFast x :> ICell

    interface ICell with
    
        member self.Command =
            5uy

        member self.Serialize writer = 
            writer.Write self.X