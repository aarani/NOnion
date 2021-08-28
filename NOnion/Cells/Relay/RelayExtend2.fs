namespace NOnion.Cells.Relay

open NOnion
open NOnion.Utility

(*
    Link specifiers describe the next node in the circuit and how to
    connect to it. Recognized specifiers are:

       [00] TLS-over-TCP, IPv4 address
            A four-byte IPv4 address plus two-byte ORPort
       [01] TLS-over-TCP, IPv6 address
            A sixteen-byte IPv6 address plus two-byte ORPort
       [02] Legacy identity
            A 20-byte SHA1 identity fingerprint. At most one may be listed.
       [03] Ed25519 identity
            A 32-byte Ed25519 identity fingerprint. At most one may
            be listed.
*)

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

(*
    To extend an existing circuit, the client sends an EXTEND or EXTEND2
    relay cell to the last node in the circuit.

    An EXTEND2 cell's relay payload contains:

        NSPEC      (Number of link specifiers)     [1 byte]
            NSPEC times:
            LSTYPE (Link specifier type)           [1 byte]
            LSLEN  (Link specifier length)         [1 byte]
            LSPEC  (Link specifier)                [LSLEN bytes]
        HTYPE      (Client Handshake Type)         [2 bytes]
        HLEN       (Client Handshake Data Len)     [2 bytes]
        HDATA      (Client Handshake Data)         [HLEN bytes]
*)

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
