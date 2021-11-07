namespace NOnion.Cells.Relay

open System.IO
open System.Security.Cryptography

open NOnion
open NOnion.Cells
open NOnion.Utility

type EndReason =
    | Misc = 1uy
    | ResolveFailed = 2uy
    | ConnectionRefused = 3uy
    | ExitPolicy = 4uy
    | Destroy = 5uy
    | Done = 6uy
    | Timeout = 7uy
    | NoRoute = 8uy
    | Hibernating = 9uy
    | Internal = 10uy
    | ResourceLimit = 11uy
    | ConnectionReset = 12uy
    | TorProtocolViolation = 13uy
    | NotDirectory = 14uy

type RelayData =
    | RelayBegin of RelayBegin
    | RelayData of Data: array<byte>
    | RelayEnd of EndReason
    | RelayConnected of Data: array<byte>
    | RelaySendMe
    | RelayExtend
    | RelayExtended
    | RelayTruncate
    | RelayTruncated of DestroyReason
    | RelayDrop
    | RelayResolve
    | RelayResolved
    | RelayBeginDirectory
    | RelayExtend2 of RelayExtend2
    | RelayExtended2 of RelayExtended2
    | RelayEstablishIntro of RelayEstablishIntro
    | RelayEstablishRendezvous of array<byte>
    | RelayEstablishedIntro
    | RelayEstablishedRendezvous
    | RelayIntroduce1 of RelayIntroduce
    | RelayIntroduce2 of RelayIntroduce
    | RelayIntroduceAck of RelayIntroduceAck
    | RelayRendezvous1 of RelayRendezvous
    | RelayRendezvous2 of RelayRendezvous

    static member FromBytes (command: byte) (data: array<byte>) =
        use memStream = new MemoryStream(data)
        use reader = new BinaryReader(memStream)

        match command with
        | RelayCommands.RelayBegin -> RelayBegin.FromBytes reader |> RelayBegin
        | RelayCommands.RelayData -> RelayData data
        | RelayCommands.RelayEnd ->
            reader.ReadByte()
            |> LanguagePrimitives.EnumOfValue<byte, EndReason>
            |> RelayEnd
        | RelayCommands.RelayConnected -> RelayConnected data
        | RelayCommands.RelayTruncated ->
            reader.ReadByte()
            |> LanguagePrimitives.EnumOfValue<byte, DestroyReason>
            |> RelayTruncated
        | RelayCommands.RelayExtended2 ->
            RelayExtended2.FromBytes reader |> RelayExtended2
        | RelayCommands.RelayEstablishIntro ->
            RelayEstablishIntro.FromBytes reader |> RelayEstablishIntro
        | RelayCommands.RelayEstablishedIntro -> RelayEstablishedIntro
        | RelayCommands.RelayEstablishedRendezvous -> RelayEstablishedRendezvous
        | RelayCommands.RelayIntroduce1 ->
            RelayIntroduce.FromBytes reader |> RelayIntroduce1
        | RelayCommands.RelayIntroduce2 ->
            RelayIntroduce.FromBytes reader |> RelayIntroduce2
        | RelayCommands.RelayRendezvous1 ->
            RelayRendezvous.FromBytes reader |> RelayRendezvous1
        | RelayCommands.RelayRendezvous2 ->
            RelayRendezvous.FromBytes reader |> RelayRendezvous2
        | RelayCommands.RelayIntroduceAck ->
            RelayIntroduceAck.FromBytes reader |> RelayIntroduceAck
        | _ -> failwith "Unsupported command"

    member self.GetCommand() : byte =
        match self with
        | RelayBegin _ -> RelayCommands.RelayBegin
        | RelayBeginDirectory -> RelayCommands.RelayBeginDirectory
        | RelayConnected _ -> RelayCommands.RelayConnected
        | RelayData _ -> RelayCommands.RelayData
        | RelaySendMe _ -> RelayCommands.RelaySendMe
        | RelayExtend2 _ -> RelayCommands.RelayExtend2
        | RelayEstablishIntro _ -> RelayCommands.RelayEstablishIntro
        | RelayEstablishRendezvous _ -> RelayCommands.RelayEstablishRendezvous
        | RelayEnd _ -> RelayCommands.RelayEnd
        | RelayIntroduce1 _ -> RelayCommands.RelayIntroduce1
        | RelayIntroduce2 _ -> RelayCommands.RelayIntroduce2
        | RelayRendezvous1 _ -> RelayCommands.RelayRendezvous1
        | RelayRendezvous2 _ -> RelayCommands.RelayRendezvous2
        | RelayIntroduceAck _ -> RelayCommands.RelayIntroduceAck
        | _ -> failwith "Not implemeted yet"

    member self.ToBytes() =
        match self with
        | RelayBegin relayBegin -> relayBegin.ToBytes()
        | RelayConnected data -> data
        | RelayData data -> data
        | RelaySendMe _ -> Array.zeroCreate 3
        | RelayEnd reason -> reason |> byte |> Array.singleton
        | RelayExtend2 extend2 -> extend2.ToBytes()
        | RelayEstablishIntro establishIntro -> establishIntro.ToBytes true true
        | RelayEstablishRendezvous cookie -> cookie
        | RelayIntroduceAck introduceAck -> introduceAck.ToBytes()
        | RelayIntroduce1 introducePayload
        | RelayIntroduce2 introducePayload -> introducePayload.ToBytes()
        | RelayRendezvous1 rendezvousPayload
        | RelayRendezvous2 rendezvousPayload -> rendezvousPayload.ToBytes()
        | _ -> Array.zeroCreate 0

type CellPlainRelay =
    {
        Recognized: uint16
        StreamId: uint16
        Digest: array<byte>
        Data: RelayData
        Padding: array<byte>
    }

    static member Create
        (streamId: uint16)
        (data: RelayData)
        (digest: array<byte>)
        =
        let payload = data.ToBytes()

        let paddingLen = Constants.MaximumRelayPayloadLength - payload.Length

        let padding = Array.zeroCreate<byte> paddingLen

        RandomNumberGenerator
            .Create()
            .GetNonZeroBytes padding

        Array.fill
            padding
            0
            (min padding.Length Constants.PaddingZeroPrefixLength)
            0uy

        {
            Recognized = 0us
            StreamId = streamId
            Data = data
            Digest = digest
            Padding = padding
        }

    static member FromBytes(bytes: array<byte>) =
        use memStream = new MemoryStream(bytes)
        use reader = new BinaryReader(memStream)
        let relayCommand = reader.ReadByte()
        let recognized = BinaryIO.ReadBigEndianUInt16 reader
        let streamId = BinaryIO.ReadBigEndianUInt16 reader
        let digest = reader.ReadBytes Constants.RelayDigestLength

        let data =
            BinaryIO.ReadBigEndianUInt16 reader |> int |> reader.ReadBytes

        let padding =
            reader.ReadBytes(Constants.MaximumRelayPayloadLength - data.Length)

        {
            Recognized = recognized
            StreamId = streamId
            Digest = digest
            Data = RelayData.FromBytes relayCommand data
            Padding = padding
        }

    member self.ToBytes(emptyDigest: bool) : array<byte> =
        use memStream = new MemoryStream(Constants.FixedPayloadLength)
        use writer = new BinaryWriter(memStream)
        self.Data.GetCommand() |> writer.Write

        self.Recognized |> BinaryIO.WriteUInt16BigEndian writer

        self.StreamId |> BinaryIO.WriteUInt16BigEndian writer

        let digest =
            if emptyDigest then
                Array.zeroCreate<byte> Constants.RelayDigestLength
            else
                self.Digest

        digest |> writer.Write

        self.Data.ToBytes()
        |> Array.length
        |> uint16
        |> BinaryIO.WriteUInt16BigEndian writer

        self.Data.ToBytes() |> writer.Write
        self.Padding |> writer.Write

        memStream.ToArray()
