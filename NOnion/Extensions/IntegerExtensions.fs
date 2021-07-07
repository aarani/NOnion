namespace NOnion.Extensions

open System

module IntegerExtensions =
    type System.UInt16 with

        member self.ToBigEndianByteArray (): array<byte> =
            let maybeLEbytes = BitConverter.GetBytes self

            match BitConverter.IsLittleEndian with
            | true -> maybeLEbytes |> Array.rev
            | false -> maybeLEbytes

        static member FromBigEndianByteArray (bytes: array<byte>): uint16 =
            let bytesForBitConverter =
                match BitConverter.IsLittleEndian with
                | true -> bytes |> Array.rev
                | false -> bytes

            BitConverter.ToUInt16 (bytesForBitConverter, 0)

    type System.UInt32 with

        member self.ToBigEndianByteArray (): array<byte> =
            let maybeLEbytes = BitConverter.GetBytes self

            match BitConverter.IsLittleEndian with
            | true -> maybeLEbytes |> Array.rev
            | false -> maybeLEbytes

        static member FromBigEndianByteArray (bytes: array<byte>): uint32 =
            let bytesForBitConverter =
                match BitConverter.IsLittleEndian with
                | true -> bytes |> Array.rev
                | false -> bytes

            BitConverter.ToUInt32 (bytesForBitConverter, 0)
