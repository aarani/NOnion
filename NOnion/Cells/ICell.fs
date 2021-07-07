namespace NOnion.Cells

open System.IO

// NOTE: A DU named `Cell` may be preferable to this interface if its number of cases is statically
// bound.
type ICell =
    abstract Command: byte
    abstract Serialize: BinaryWriter -> unit