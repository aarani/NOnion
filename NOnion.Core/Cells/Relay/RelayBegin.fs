namespace NOnion.Core.Cells.Relay

open System
open System.IO
open System.Text

open NOnion.Core
open NOnion.Core.Cells
open NOnion.Core.Utility

type RelayBegin =
    {
        Address: string
        Flags: uint
    }

    static member FromBytes(reader: BinaryReader) =
        let rec readAddress(state: string) =
            let nextChar = reader.ReadChar()

            if nextChar <> Char.MinValue then
                readAddress(state + string(nextChar))
            else
                state

        {
            Address = readAddress String.Empty
            Flags = BinaryIO.ReadBigEndianUInt32 reader
        }

    member self.ToBytes() =
        Array.concat
            [
                self.Address + string Char.MinValue |> Encoding.ASCII.GetBytes
                IntegerSerialization.FromUInt32ToBigEndianByteArray self.Flags
            ]
