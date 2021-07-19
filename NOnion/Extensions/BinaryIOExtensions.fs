namespace NOnion.Extensions

open System.IO

module BinaryIOExtensions =
    module BinaryWriter =
        let WriteUInt16BigEndian (writer: BinaryWriter) (num: uint16) : unit =
            num |> IntegerExtensions.UInt16.ToBigEndianByteArray |> writer.Write

        let WriteUInt32BigEndian (writer: BinaryWriter) (num: uint32) : unit =
            num |> IntegerExtensions.UInt32.ToBigEndianByteArray |> writer.Write

    module BinaryReader =

        let ReadBigEndianUInt16 (reader: BinaryReader) : uint16 =
            sizeof<uint16>
            |> reader.ReadBytes
            |> IntegerExtensions.UInt16.FromBigEndianByteArray

        let ReadBigEndianUInt32 (reader: BinaryReader) : uint32 =
            sizeof<uint32>
            |> reader.ReadBytes
            |> IntegerExtensions.UInt32.FromBigEndianByteArray
