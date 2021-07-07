namespace NOnion.Cells

type ICell =
    abstract Command: byte
    abstract Serialize: System.IO.BinaryWriter -> unit
