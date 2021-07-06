namespace NOnion.Cells

open System.IO

type ICell =
    abstract Command: byte
    abstract Serialize: BinaryWriter -> unit
