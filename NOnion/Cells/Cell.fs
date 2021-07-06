namespace NOnion.Cells

open System.IO

[<AbstractClass>]
type Cell () =
    abstract Command: byte with get

    abstract member Serialize: BinaryWriter -> unit
    abstract member Deserialize: BinaryReader -> unit
