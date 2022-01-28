namespace NOnion.Core.Cells.Relay

open System.IO

open NOnion.Core
open NOnion.Core.Cells
open NOnion.Core.Utility

// Specification (https://github.com/torproject/torspec/blob/main/tor-spec.txt#L1085)
type RelayExtended2 =
    {
        HandshakeData: array<byte>
    }

    static member FromBytes(reader: BinaryReader) =
        {
            HandshakeData =
                BinaryIO.ReadBigEndianUInt16 reader |> int |> reader.ReadBytes
        }

    interface ICreatedCell with
        member self.ServerHandshake =
            self.HandshakeData |> Array.take Constants.NTorPublicKeyLength

        member self.DerivativeKey =
            self.HandshakeData
            |> Array.skip Constants.NTorPublicKeyLength
            |> Array.take Constants.NTorAuthDataLength
