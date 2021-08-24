namespace NOnion.Cells.Relay

open System.IO

open NOnion
open NOnion.Cells

type CellEncryptedRelay =
    {
        EncryptedData: array<byte>
        Early: bool
    }

    static member Deserialize (reader: BinaryReader) (early: bool) =
        {
            EncryptedData = reader.ReadBytes Constants.FixedPayloadLength
            Early = early
        }
        :> ICell

    interface ICell with

        member self.Command =
            if self.Early then
                9uy
            else
                3uy

        member self.Serialize writer =
            writer.Write self.EncryptedData
