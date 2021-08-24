namespace NOnion.Cells

open System.IO

open NOnion.Utility

type CellCreated2 =
    private
        {
            HandshakeData: array<byte>
        }

    static member Deserialize (reader: BinaryReader) =
        {
            HandshakeData =
                BinaryIO.ReadBigEndianUInt16 reader |> int |> reader.ReadBytes
        }
        :> ICell

    interface ICell with

        member __.Command = 11uy

        member self.Serialize writer =
            self.HandshakeData.Length
            |> uint16
            |> BinaryIO.WriteUInt16BigEndian writer

            writer.Write self.HandshakeData

    interface ICreatedCell with
        member self.ServerHandshake = self.HandshakeData |> Array.take 32

        member self.DerivativeKey = self.HandshakeData |> Array.skip 32
