namespace NOnion.Helpers

open System.IO

open NOnion.Cells

module CommandsHelper =
    [<Literal>]
    let CellAuthChallengeCommand = 130uy
    [<Literal>]
    let CellCertsCommand = 129uy
    [<Literal>]
    let CellVersionCommand = 7uy
    [<Literal>]
    let CellNetInfoCommand = 8uy
    [<Literal>]
    let CellCreateFastCommand = 5uy
    [<Literal>]
    let CellCreatedFastCommand = 6uy

    let IsVariableLength (command: byte): bool =
        command = 7uy || command >= 128uy

    let GetCell (command: byte) (reader: BinaryReader): ICell =
        match command with 
        | CellAuthChallengeCommand ->
            CellAuthChallenge.Deserialize reader
        | CellCertsCommand ->
            CellCerts.Deserialize reader
        | CellVersionCommand ->
            CellVersions.Deserialize reader
        | CellNetInfoCommand ->
            CellNetInfo.Deserialize reader
        | CellCreateFastCommand ->
            CellCreateFast.Deserialize reader
        | CellCreatedFastCommand ->
            CellCreatedFast.Deserialize reader
        | _ -> failwith "not implemented!"
