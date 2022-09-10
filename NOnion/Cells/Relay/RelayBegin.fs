namespace NOnion.Cells.Relay

open System
open System.IO
open System.Text

open NOnion
open NOnion.Cells
open NOnion.Utility

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
            Flags = 0u
        }

    member self.ToBytes() =
        Array.concat
            [
                self.Address + string Char.MinValue |> Encoding.ASCII.GetBytes
                IntegerSerialization.FromUInt32ToBigEndianByteArray self.Flags
            ]
