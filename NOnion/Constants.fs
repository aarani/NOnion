namespace NOnion

open System
open System.Text

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

    let internal SupportedProtocolVersion: array<uint16> = [| 3us |]

    (*
     *  Existing Tor implementations choose their CircID values at random from
     *  among the available unused values.  To avoid distinguishability, new
     *  implementations should do the same. Implementations MAY give up and stop
     *  attempting to build new circuits on a channel, if a certain number of
     *  randomly chosen CircID values are all in use (today's Tor stops after 64).
     *)
    let internal MaxCircuitIdGenerationRetry = 64

    // FixedPayloadLength - 11 (header length)
    let internal MaximumRelayPayloadLength = 498

    // First 4 bytes of the padding for relay cell should be 0
    let internal PaddingZeroPrefixLength = 4

    let internal RelayDigestLength = 4

    let internal RelayDigestOffset = 5

    let internal RelayRecognizedOffset = 1

    let internal RecognizedDefaultValue = 0us

    //TODO: Add support for +4 tor protocol with 4 byte circuit ids
    let internal CircuitIdLength = 2

    let internal DefaultCircuitId = 0us

    // Command (1 byte) + CircuitId (2 byte)
    let internal PacketHeaderLength = 3

    let internal CommandOffset = CircuitIdLength

    let internal VariableLengthBodyPrefixLength = 2

    let internal DefaultStreamId = 0us

    //TODO: Should be updatable from consensus
    let internal DefaultCircuitLevelWindowParams = (1000, 100)
    let internal DefaultStreamLevelWindowParams = (500, 50)

    let internal DeflateStreamHeaderLength = 2

    // Time limit used for Create and Extend operations
    let internal CircuitOperationTimeout = TimeSpan.FromSeconds 10.

    // Time limit used for StreamBegin operation
    let internal StreamCreationTimeout = TimeSpan.FromSeconds 10.

    // Time limit used for http requests
    let internal HttpResponseTimeout = TimeSpan.FromMinutes 3.

    // Time limit used for receving data in stream
    let internal StreamReceiveTimeout = TimeSpan.FromSeconds 1.

    // NTor Handshake Constants
    let private nTorProtoIdStr = "ntor-curve25519-sha256-1"
    let internal NTorProtoId = nTorProtoIdStr |> Encoding.ASCII.GetBytes
    let internal NTorTMac = nTorProtoIdStr + ":mac" |> Encoding.ASCII.GetBytes

    let internal NTorTKey =
        nTorProtoIdStr + ":key_extract" |> Encoding.ASCII.GetBytes

    let internal NTorTVerify =
        nTorProtoIdStr + ":verify" |> Encoding.ASCII.GetBytes

    let internal NTorMExpand =
        nTorProtoIdStr + ":key_expand" |> Encoding.ASCII.GetBytes

    let internal NTorAuthInputSuffix =
        nTorProtoIdStr + "Server" |> Encoding.ASCII.GetBytes

    let internal NTorPublicKeyLength = 32
    let internal NTorAuthDataLength = 32

    let internal EstablishIntroDataPrefix = "Tor establish-intro cell v1"

    let internal DefaultHSDirInterval = 1440

    let internal RotationTimeOffset = TimeSpan.FromHours 12.0

    let internal Ed25519BasePointString =
        "(15112221349535400772501151409588531511454012693041857206046113283949847762202,46316835694926478169428394003475163141307993866256225615783033603165251855960)"
        |> Encoding.ASCII.GetBytes

    let internal HiddenServiceBlindString =
        "Derive temporary signing key"
        |> Encoding.ASCII.GetBytes
        |> Array.append (Array.singleton 0uy)

    let RendezvousCookieLength = 20

    let internal RelayIntroduceKeyType = 1
