namespace NOnion.Cells

open System
open System.IO

[<RequireQualifiedAccess>]
module Command =
    
    let [<Literal>] Certs = 129uy
    let [<Literal>] AuthChallenge = 130uy
    let [<Literal>] Version = 7uy
    let [<Literal>] NetInfo = 8uy
    let [<Literal>] CreateFast = 5uy
    let [<Literal>] CreatedFast = 6uy

    let IsVariableLength (command: byte): bool =
        command = 7uy || command >= 128uy

    /// Serialize a cell, assuming its command has already been written.
    /// TODO: make a more independent Cell.Serialize function that writes its own command byte?
    let SerializeCell writer (cell: ICell) =
        cell.Serialize writer

    /// Deserialize a cell of the given command type that has already been read.
    /// TODO: make a more independent Cell.Deserialize function that reads its own command byte?
    let DeserializeCell (reader: BinaryReader) (command: byte): ICell =
        match command with
        | Certs -> CellCerts.Deserialize reader
        | AuthChallenge -> CellAuthChallenge.Deserialize reader
        | Version -> CellVersions.Deserialize reader
        | NetInfo -> CellNetInfo.Deserialize reader
        | CreateFast -> CellCreateFast.Deserialize reader
        | CreatedFast -> CellCreatedFast.Deserialize reader
        | _ -> raise <| NotImplementedException ()