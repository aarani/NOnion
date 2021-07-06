namespace NOnion.Cells

open NOnion
open NOnion.Extensions.BinaryIOExtensions



type CellCreateFast () =

    [<DefaultValue>]
    val mutable X: array<byte>

    interface ICell with
    
        member self.Command =
            5uy

        member self.Serialize writer = 
            writer.Write self.X

        member self.Deserialize reader = 
            self.X <-
                reader.ReadBytes Constants.HashLength