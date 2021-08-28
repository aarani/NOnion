namespace NOnion.Cells

open System.IO

open NOnion.Utility.BinaryIO

(*
    Relevant certType values are:
       1: Link key certificate certified by RSA1024 identity
       2: RSA1024 Identity certificate, self-signed.
       3: RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key.
       4: Ed25519 signing key, signed with identity key.
       5: TLS link certificate, signed with ed25519 signing key.
       6: Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key.
       7: Ed25519 identity, signed with RSA identity.
*)

type Cert =
    {
        Type: byte
        Certificate: array<byte>
    }

(*
    The CERTS cell describes the keys that a Tor instance is claiming
    to have.  It is a variable-length cell.  Its payload format is:

         N: Number of certs in cell            [1 octet]
         N times:
            CertType                           [1 octet]
            CLEN                               [2 octets]
            Certificate                        [CLEN octets]

    Any extra octets at the end of a CERTS cell MUST be ignored.

    The certificate format for certificate types 1-3 is DER encoded
       X509.  For others, the format is as documented in cert-spec.txt.
       Note that type 7 uses a different format from types 4-6.

    A CERTS cell may have no more than one certificate of each CertType.
*)

type CellCerts =
    {
        Certs: seq<Cert>
    }

    static member Deserialize (reader: BinaryReader) =

        let rec readCertificates certificates n =
            if n = 0 then
                certificates
            else
                let certificate =
                    {
                        Cert.Type = reader.ReadByte ()
                        Cert.Certificate =
                            ReadBigEndianUInt16 reader
                            |> int
                            |> reader.ReadBytes
                    }

                readCertificates (certificates @ [ certificate ]) (n - 1)

        let certificatesCount = reader.ReadByte () |> int
        let certs = readCertificates List.empty certificatesCount

        {
            Certs = certs
        }
        :> ICell

    interface ICell with

        member __.Command = 129uy

        member self.Serialize writer =

            let rec writeCertificates (certificates: seq<Cert>) =
                match Seq.tryHead certificates with
                | None -> ()
                | Some certificate ->
                    writer.Write certificate.Type

                    certificate.Certificate.Length
                    |> uint16
                    |> WriteUInt16BigEndian writer

                    writer.Write certificate.Certificate
                    certificates |> Seq.tail |> writeCertificates

            self.Certs |> Seq.length |> uint8 |> writer.Write
            writeCertificates self.Certs
