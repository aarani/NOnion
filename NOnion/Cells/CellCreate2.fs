namespace NOnion.Cells

open Microsoft.FSharp.Core
open System.IO

open NOnion
open NOnion.Utility

(*
    A CREATE2 cell contains:
        HTYPE     (Client Handshake Type)     [2 bytes]
        HLEN      (Client Handshake Data Len) [2 bytes]
        HDATA     (Client Handshake Data)     [HLEN bytes]

    Recognized handshake types are:
        0x0000  TAP  -- the original Tor handshake; see 5.1.3
        0x0001  reserved
        0x0002  ntor -- the ntor+curve25519+sha256 handshake; see 5.1.4

    Servers always reply to a successful CREATE with a CREATED, and to a
       successful CREATE2 with a CREATED2.  On failure, a server sends a
       DESTROY cell to tear down the circuit.
*)

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
