namespace NOnion.Helpers

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

    let GetCell (command: byte): Cell =
        match command with 
        | CellAuthChallengeCommand ->
            CellAuthChallenge() :> Cell
        | CellCertsCommand ->
            CellCerts() :> Cell
        | CellVersionCommand ->
            CellVersions() :> Cell
        | CellNetInfoCommand ->
            CellNetInfo() :> Cell
        | CellCreateFastCommand ->
            CellCreateFast() :> Cell
        | CellCreatedFastCommand ->
            CellCreatedFast() :> Cell
        | _ -> failwith "not implemented!"
