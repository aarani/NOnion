namespace NOnion.Cells.Relay

open NOnion
open NOnion.Utility

type LinkSpecifierType =
    | TLSOverTCPV4 = 0uy
    | TLSOverTCPV6 = 1uy
    | LegacyIdentity = 2uy
    | Ed25519Identity = 3uy

type LinkSpecifier =
    {
        Type: LinkSpecifierType
        Data: array<byte>
    }

    member self.ToBytes () =
        Array.concat [ [|
                           self.Type |> byte
                           self.Data.Length |> byte
                       |]
                       self.Data ]

type RelayExtend2 =
    {
        LinkSpecifiers: List<LinkSpecifier>
        HandshakeType: HandshakeType
        HandshakeData: array<byte>
    }

    member self.ToBytes () =
        Array.concat [ self.LinkSpecifiers.Length |> byte |> Array.singleton

                       self.LinkSpecifiers
                       |> List.map (fun link -> link.ToBytes ())
                       |> Array.concat

                       self.HandshakeType
                       |> uint16
                       |> IntegerSerialization.FromUInt16ToBigEndianByteArray

                       self.HandshakeData.Length
                       |> uint16
                       |> IntegerSerialization.FromUInt16ToBigEndianByteArray

                       self.HandshakeData ]
