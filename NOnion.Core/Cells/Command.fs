namespace NOnion.Core.Cells

open System
open System.IO

open NOnion.Core.Cells.Relay

[<RequireQualifiedAccess>]
module Command =

    [<Literal>]
    let Certs = 129uy

    [<Literal>]
    let AuthChallenge = 130uy

    [<Literal>]
    let Padding = 0uy

    [<Literal>]
    let Relay = 3uy

    [<Literal>]
    let Destroy = 4uy

    [<Literal>]
    let Version = 7uy

    [<Literal>]
    let NetInfo = 8uy

    [<Literal>]
    let RelayEarly = 9uy

    [<Literal>]
    let CreateFast = 5uy

    [<Literal>]
    let CreatedFast = 6uy

    [<Literal>]
    let Create2 = 10uy

    [<Literal>]
    let Created2 = 11uy

    let IsVariableLength(command: byte) : bool =
        command = 7uy || command >= 128uy

    /// Serialize a cell, assuming its command has already been written.
    /// TODO: make a more independent Cell.Serialize function that writes its own command byte?
    let SerializeCell writer (cell: ICell) =
        cell.Serialize writer

    /// Deserialize a cell of the given command type that has already been read.
    /// TODO: make a more independent Cell.Deserialize function that reads its own command byte?
    let DeserializeCell (reader: BinaryReader) (command: byte) : ICell =
        match command with
        | Certs -> CellCerts.Deserialize reader
        | AuthChallenge -> CellAuthChallenge.Deserialize reader
        | Version -> CellVersions.Deserialize reader
        | NetInfo -> CellNetInfo.Deserialize reader
        | CreateFast -> CellCreateFast.Deserialize reader
        | CreatedFast -> CellCreatedFast.Deserialize reader
        | Relay -> CellEncryptedRelay.Deserialize reader false
        | RelayEarly -> CellEncryptedRelay.Deserialize reader true
        | Padding -> CellPadding.Deserialize reader
        | Destroy -> CellDestroy.Deserialize reader
        | Create2 -> CellCreate2.Deserialize reader
        | Created2 -> CellCreated2.Deserialize reader
        | _ -> raise <| NotImplementedException()

    // Is there any non generic way for this?
    let GetCommandByCellType<'T when 'T :> ICell>() =
        match typeof<'T> with
        | t when t = typeof<CellCerts> -> Certs
        | t when t = typeof<CellAuthChallenge> -> AuthChallenge
        | t when t = typeof<CellVersions> -> Version
        | t when t = typeof<CellNetInfo> -> NetInfo
        | t when t = typeof<CellCreateFast> -> CreateFast
        | t when t = typeof<CellCreatedFast> -> CreatedFast
        | t when t = typeof<CellEncryptedRelay> -> Relay
        | t when t = typeof<CellPadding> -> Padding
        | t when t = typeof<CellDestroy> -> Destroy
        | t when t = typeof<CellCreate2> -> Create2
        | t when t = typeof<CellCreated2> -> Created2
        | _ -> raise <| NotImplementedException()
