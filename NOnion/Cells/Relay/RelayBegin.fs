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
            // This flag apparently doesn't exists in Tor's service stream begin
            // calls, which caused deserialization excpetion, since we don't really
            // use this flag, we ignore it when deserializing for now.
            Flags = 0u
        }

    member self.ToBytes() =
        Array.concat
            [
                self.Address + string Char.MinValue |> Encoding.ASCII.GetBytes
                IntegerSerialization.FromUInt32ToBigEndianByteArray self.Flags
            ]
