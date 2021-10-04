namespace NOnion.Cells.Relay

module RelayCommands =

    [<Literal>]
    let RelayData = 2uy

    [<Literal>]
    let RelayEnd = 3uy

    [<Literal>]
    let RelayConnected = 4uy

    [<Literal>]
    let RelaySendMe = 5uy

    [<Literal>]
    let RelayTruncated = 9uy

    [<Literal>]
    let RelayBeginDirectory = 13uy

    [<Literal>]
    let RelayExtend2 = 14uy

    [<Literal>]
    let RelayExtended2 = 15uy

    [<Literal>]
    let RelayEstablishIntro = 32uy

    [<Literal>]
    let RelayEstablishedIntro = 38uy

    [<Literal>]
    let RelayIntroduce1 = 34uy

    [<Literal>]
    let RelayIntroduce2 = 35uy

    [<Literal>]
    let RelayIntroduceAck = 40uy

    [<Literal>]
    let RelayEstablishRendezvous = 33uy

    [<Literal>]
    let RelayEstablishedRendezvous = 39uy
