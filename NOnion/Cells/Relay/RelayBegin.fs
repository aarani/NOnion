namespace NOnion.Cells.Relay

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

    static member FromBytes (reader: BinaryReader) =
        let rec readAddress (state: string) =
            let nextChar = reader.ReadChar ()

            if nextChar <> '\000' then
                readAddress (state + string (nextChar))
            else
                state

        {
            Address = readAddress ""
            Flags = BinaryIO.ReadBigEndianUInt32 reader
        }

    member self.ToBytes () =
        Array.concat
            [
                self.Address + string '\000' |> Encoding.ASCII.GetBytes
                IntegerSerialization.FromUInt32ToBigEndianByteArray self.Flags
            ]
