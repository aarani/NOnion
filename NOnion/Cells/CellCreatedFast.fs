namespace NOnion.Cells

open NOnion
open NOnion.Extensions.BinaryIOExtensions



type CellCreatedFast () =

    [<DefaultValue>]
    val mutable Y: array<byte>
    [<DefaultValue>]
    val mutable DerivativeKeyData: array<byte>

    interface ICell with
    
        member self.Command =
            6uy

        member self.Serialize writer = 
            writer.Write self.Y
            writer.Write self.DerivativeKeyData

        member self.Deserialize reader = 
            self.Y <-
                reader.ReadBytes Constants.HashLength
            self.DerivativeKeyData <-
                reader.ReadBytes Constants.HashLength