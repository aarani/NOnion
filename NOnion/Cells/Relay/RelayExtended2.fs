namespace NOnion.Cells.Relay

open System.IO

open NOnion
open NOnion.Cells
open NOnion.Utility

(*
    The payload of an EXTENDED2 cell is the same as the payload of a
    CREATED2 cell.
*)

type RelayExtended2 =
    {
        HandshakeData: array<byte>
    }

    static member FromBytes (reader: BinaryReader) =
        {
            HandshakeData =
                BinaryIO.ReadBigEndianUInt16 reader |> int |> reader.ReadBytes
        }

    interface ICreatedCell with
        member self.ServerHandshake =
            self.HandshakeData |> Array.take Constants.NTorServerPublicKeyLength

        member self.DerivativeKey =
            self.HandshakeData
            |> Array.skip Constants.NTorServerPublicKeyLength
            |> Array.take Constants.NTorAuthDataLength
