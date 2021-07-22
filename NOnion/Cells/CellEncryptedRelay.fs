namespace NOnion.Cells

open System.IO

open NOnion

type CellEncryptedRelay =
    {
        EncryptedData: array<byte>
    }

    static member Deserialize (reader: BinaryReader) =
        {
            EncryptedData = reader.ReadBytes Constants.FixedPayloadLength
        }
        :> ICell

    interface ICell with

        member __.Command = 3uy

        member self.Serialize writer =
            writer.Write self.EncryptedData
