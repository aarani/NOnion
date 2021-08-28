namespace NOnion.Cells

open System.IO

open NOnion

(*
    A CREATED_FAST cell contains:

        Key material (Y)    [HASH_LEN bytes]
        Derivative key data [HASH_LEN bytes] (See 5.2.1 below)
*)

type CellCreatedFast =
    private
        {
            Y: array<byte>
            DerivativeKeyData: array<byte>
        }

    static member Deserialize (reader: BinaryReader) =
        let y = reader.ReadBytes Constants.HashLength
        let derivativeKeyData = reader.ReadBytes Constants.HashLength

        {
            Y = y
            DerivativeKeyData = derivativeKeyData
        }
        :> ICell

    interface ICell with

        member __.Command = 6uy

        member self.Serialize writer =
            writer.Write self.Y
            writer.Write self.DerivativeKeyData

    interface ICreatedCell with
        member self.ServerHandshake = self.Y

        member self.DerivativeKey = self.DerivativeKeyData
