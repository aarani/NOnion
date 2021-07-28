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

    let SupportedProtocolVersion: array<uint16> = [| 3us |]

    (*
     *  Existing Tor implementations choose their CircID values at random from
     *  among the available unused values.  To avoid distinguishability, new
     *  implementations should do the same. Implementations MAY give up and stop
     *  attempting to build new circuits on a channel, if a certain number of
     *  randomly chosen CircID values are all in use (today's Tor stops after 64).
     *)

    [<Literal>]
    let MaxCircuitIdGenerationRetry = 64
