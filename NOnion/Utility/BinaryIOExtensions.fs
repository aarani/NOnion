namespace NOnion.Utility

open System.IO

open NOnion.Utility.UInt16Extension
open NOnion.Utility.UInt32Extension

module BinaryWriterExtension =

    let WriteUInt16BigEndian (writer: BinaryWriter) (num: uint16) : unit =
        FromUInt16ToBigEndianByteArray num |> writer.Write

    let WriteUInt32BigEndian (writer: BinaryWriter) (num: uint32) : unit =
        FromUInt32ToBigEndianByteArray num |> writer.Write


module BinaryReaderExtension =
    let ReadBigEndianUInt16 (reader: BinaryReader) : uint16 =
        sizeof<uint16> |> reader.ReadBytes |> FromBigEndianByteArrayToUInt16

    let ReadBigEndianUInt32 (reader: BinaryReader) : uint32 =
        sizeof<uint32> |> reader.ReadBytes |> FromBigEndianByteArrayToUInt32
