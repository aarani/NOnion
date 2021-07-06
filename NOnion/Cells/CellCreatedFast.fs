namespace NOnion.Cells

open NOnion
open NOnion.Extensions.BinaryIOExtensions



type CellCreatedFast ()=
    inherit Cell ()

    [<DefaultValue>]
    val mutable Y: array<byte>
    [<DefaultValue>]
    val mutable DerivativeKeyData: array<byte>
    
    override self.Command =
        6uy

    override self.Serialize writer = 
        writer.Write self.Y
        writer.Write self.DerivativeKeyData

    override self.Deserialize reader = 
        self.Y <-
            reader.ReadBytes Constants.HashLength
        self.DerivativeKeyData <-
            reader.ReadBytes Constants.HashLength