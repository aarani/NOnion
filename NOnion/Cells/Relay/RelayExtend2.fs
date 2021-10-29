namespace NOnion.Cells.Relay

open System.IO
open System.Net

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

    member self.ToEndPoint() =
        match self.Type with
        | LinkSpecifierType.TLSOverTCPV4 ->
            self.Data |> Array.take 4 |> IPAddress,
            self.Data
            |> Array.skip 4
            |> Array.take 2
            |> IntegerSerialization.FromBigEndianByteArrayToUInt16
            |> int
        | LinkSpecifierType.TLSOverTCPV6 ->
            self.Data |> Array.take 16 |> IPAddress,
            self.Data
            |> Array.skip 16
            |> Array.take 2
            |> IntegerSerialization.FromBigEndianByteArrayToUInt16
            |> int
        | _ -> failwith "Non endpooint-type link specifier"
        |> IPEndPoint

    static member CreateFromEndPoint(endPoint: IPEndPoint) =
        let translateIPEndpoint(endpoint: IPEndPoint) =
            Array.concat
                [
                    endpoint.Address.GetAddressBytes()
                    endpoint.Port
                    |> uint16
                    |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                ]

        {
            LinkSpecifier.Type =
                match endPoint.AddressFamily with
                | Sockets.AddressFamily.InterNetwork ->
                    LinkSpecifierType.TLSOverTCPV4
                | Sockets.AddressFamily.InterNetworkV6 ->
                    LinkSpecifierType.TLSOverTCPV6
                | _ -> failwith "Unknown address family"
            Data = translateIPEndpoint endPoint
        }

    member self.ToBytes() =
        Array.concat
            [
                [|
                    self.Type |> byte
                    self.Data.Length |> byte
                |]
                self.Data
            ]

    static member Deserialize(reader: BinaryReader) =
        let linkType =
            reader.ReadByte()
            |> LanguagePrimitives.EnumOfValue<byte, LinkSpecifierType>

        let data = reader.ReadByte() |> int |> reader.ReadBytes

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

    member self.ToBytes() =
        Array.concat
            [
                self.LinkSpecifiers.Length |> byte |> Array.singleton

                self.LinkSpecifiers
                |> List.map(fun link -> link.ToBytes())
                |> Array.concat

                self.HandshakeType
                |> uint16
                |> IntegerSerialization.FromUInt16ToBigEndianByteArray

                self.HandshakeData.Length
                |> uint16
                |> IntegerSerialization.FromUInt16ToBigEndianByteArray

                self.HandshakeData
            ]
