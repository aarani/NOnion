namespace NOnion.Cells.Relay

open System.IO

open NOnion
open NOnion.Utility

type LinkSpecifierType =
    | TLSOverTCPV4 = 0uy
    | TLSOverTCPV6 = 1uy
    | LegacyIdentity = 2uy
    | Ed25519Identity = 3uy

//FIXME: Since this now used in other relay cells, consider moving this to another file
type LinkSpecifier =
    {
        Type: LinkSpecifierType
        Data: array<byte>
    }

    member self.ToBytes () =
        Array.concat
            [
                [|
                    self.Type |> byte
                    self.Data.Length |> byte
                |]
                self.Data
            ]

    static member Deserialize (reader: BinaryReader) =
        let linkType =
            reader.ReadByte ()
            |> LanguagePrimitives.EnumOfValue<byte, LinkSpecifierType>

        let data = reader.ReadByte () |> int |> reader.ReadBytes

        {
            Type = linkType
            Data = data
        }


type RelayExtend2 =
    {
        LinkSpecifiers: List<LinkSpecifier>
        HandshakeType: HandshakeType
        HandshakeData: array<byte>
    }

    member self.ToBytes () =
        Array.concat
            [
                self.LinkSpecifiers.Length |> byte |> Array.singleton

                self.LinkSpecifiers
                |> List.map (fun link -> link.ToBytes ())
                |> Array.concat

                self.HandshakeType
                |> uint16
                |> IntegerSerialization.FromUInt16ToBigEndianByteArray

                self.HandshakeData.Length
                |> uint16
                |> IntegerSerialization.FromUInt16ToBigEndianByteArray

                self.HandshakeData
            ]
