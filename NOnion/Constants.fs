namespace NOnion

[<RequireQualifiedAccess>]
module Constants =

    [<Literal>]
    let ChallangeLength = 32

    [<Literal>]
    let FixedPayloadLength = 509

    [<Literal>]
    let HashLength = 20

    [<Literal>]
    let KeyLength = 16

    (* Amount of bytes needed for generating keys and digest during KDF = 2 * KeyLength + 3 * HashLength *)
    [<Literal>]
    let KdfLength = 92
