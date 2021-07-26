namespace NOnion.Cells

open System.IO

open NOnion
open NOnion.Utility
open System.Net
open NOnion.Crypto
open System.Security.Cryptography

type RelayData =
    | RelayBegin
    | RelayData of Data: array<byte>
    | RelayEnd of Reason: byte
    | RelayConnected of Data: array<byte>
    | RelaySendMe
    | RelayExtend
    | RelayExtended
    | RelayTruncate
    | RelayTruncated
    | RelayDrop
    | RelayResolve
    | RelayResolved
    | RelayBeginDirectory
    | RelayExtend2
    | RelayExtended2

    static member FromBytes (command: byte) (data: array<byte>) =
        use memStream = new MemoryStream (data)
        use reader = new BinaryReader (memStream)

        match command with
        | 2uy -> RelayData data
        | 3uy -> RelayEnd (reader.ReadByte ())
        | 4uy -> RelayConnected data
        | _ -> failwith "Unsupported command"

    member self.GetCommand () : byte =
        match self with
        | RelayBeginDirectory -> 13uy
        | RelayData _ -> 2uy
        | _ -> failwith ""

    member self.ToBytes () =
        match self with
        | RelayData data -> data
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
        let payload = data.ToBytes ()

        let padding =
            Array.zeroCreate<byte> (
                Constants.FixedPayloadLength - 11 - payload.Length
            )

        RandomNumberGenerator
            .Create()
            .GetNonZeroBytes padding

        Array.fill padding 0 (min padding.Length 4) 0uy

        {
            Recognized = 0us
            StreamId = streamId
            Data = data
            Digest = digest
            Padding = padding
        }

    static member FromBytes (bytes: array<byte>) =
        use memStream = new MemoryStream (bytes)
        use reader = new BinaryReader (memStream)
        let relayCommand = reader.ReadByte ()
        let recognized = BinaryIO.ReadBigEndianUInt16 reader
        let streamId = BinaryIO.ReadBigEndianUInt16 reader
        let digest = reader.ReadBytes 4

        let data =
            BinaryIO.ReadBigEndianUInt16 reader |> int |> reader.ReadBytes

        let padding =
            reader.ReadBytes (Constants.FixedPayloadLength - 11 - data.Length)

        {
            Recognized = recognized
            StreamId = streamId
            Digest = digest
            Data = RelayData.FromBytes relayCommand data
            Padding = padding
        }

    member self.ToBytes (emptyDigest: bool) : array<byte> =
        use memStream = new MemoryStream (Constants.FixedPayloadLength)
        use writer = new BinaryWriter (memStream)
        self.Data.GetCommand () |> writer.Write

        self.Recognized |> BinaryIO.WriteUInt16BigEndian writer

        self.StreamId |> BinaryIO.WriteUInt16BigEndian writer

        let digest =
            match emptyDigest with
            | true -> Array.zeroCreate<byte> 4
            | false -> self.Digest

        digest |> writer.Write

        self.Data.ToBytes ()
        |> Array.length
        |> uint16
        |> BinaryIO.WriteUInt16BigEndian writer

        self.Data.ToBytes () |> writer.Write
        self.Padding |> writer.Write

        memStream.ToArray ()
