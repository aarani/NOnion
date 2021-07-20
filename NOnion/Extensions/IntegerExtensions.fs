namespace NOnion.Extensions

open System

module IntegerExtensions =
    module UInt16 =
        let ToBigEndianByteArray (value: uint16) : array<byte> =
            let maybeLittleEndianBytes = BitConverter.GetBytes value

            if BitConverter.IsLittleEndian then
                maybeLittleEndianBytes |> Array.rev
            else
                maybeLittleEndianBytes

        let FromBigEndianByteArray (bytes: array<byte>) : uint16 =
            let bytesForBitConverter =
                if BitConverter.IsLittleEndian then
                    bytes |> Array.rev
                else
                    bytes

            BitConverter.ToUInt16 (bytesForBitConverter, 0)

    module UInt32 =
        let ToBigEndianByteArray (value: uint32) : array<byte> =
            let maybeLittleEndianBytes = BitConverter.GetBytes value

            if BitConverter.IsLittleEndian then
                maybeLittleEndianBytes |> Array.rev
            else
                maybeLittleEndianBytes

        let FromBigEndianByteArray (bytes: array<byte>) : uint32 =
            let bytesForBitConverter =
                if BitConverter.IsLittleEndian then
                    bytes |> Array.rev
                else
                    bytes

            BitConverter.ToUInt32 (bytesForBitConverter, 0)
