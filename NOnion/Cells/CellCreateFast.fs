namespace NOnion.Cells

open NOnion
open NOnion.Extensions.BinaryIOExtensions



type CellCreateFast ()=
    inherit Cell ()

    [<DefaultValue>]
    val mutable X: array<byte>
    
    override self.Command =
        5uy

    override self.Serialize writer = 
        writer.Write self.X

    override self.Deserialize reader = 
        self.X <-
            reader.ReadBytes Constants.HashLength