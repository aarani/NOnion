namespace NOnion.Cells

open Microsoft.FSharp.Core
open System.IO

open NOnion
open NOnion.Utility

// Specification (https://github.com/torproject/torspec/blob/main/tor-spec.txt#L466)
type CellCreate2 =
    {
        HandshakeType: HandshakeType
        HandshakeData: array<byte>
    }

    static member Deserialize (reader: BinaryReader) =
        {
            HandshakeType =
                BinaryIO.ReadBigEndianUInt16 reader
                |> LanguagePrimitives.EnumOfValue<uint16, HandshakeType>

            HandshakeData =
                BinaryIO.ReadBigEndianUInt16 reader |> int |> reader.ReadBytes
        }
        :> ICell

    interface ICell with

        member __.Command = 10uy

        member self.Serialize writer =
            self.HandshakeType |> uint16 |> BinaryIO.WriteUInt16BigEndian writer

            self.HandshakeData.Length
            |> uint16
            |> BinaryIO.WriteUInt16BigEndian writer

            writer.Write self.HandshakeData
