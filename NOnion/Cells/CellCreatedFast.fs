namespace NOnion.Cells

open System.IO

open NOnion
open NOnion.Extensions.BinaryIOExtensions

type CellCreatedFast (y: array<byte>, derivativeKeyData: array<byte>) =

    member self.Y = y

    member self.DerivativeKeyData = derivativeKeyData
    
    static member Deserialize (reader : BinaryReader) =
        let y = reader.ReadBytes Constants.HashLength
        let derivativeKeyData = reader.ReadBytes Constants.HashLength
        CellCreatedFast (y, derivativeKeyData) :> ICell

    interface ICell with
    
        member self.Command =
            6uy

        member self.Serialize writer = 
            writer.Write self.Y
            writer.Write self.DerivativeKeyData