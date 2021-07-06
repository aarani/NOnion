namespace NOnion.Cells

open NOnion
open NOnion.Extensions.BinaryIOExtensions

type Cert = {
    Type: byte
    Certificate: array<byte>
}

type CellCerts () =

    [<DefaultValue>]
    val mutable Certs: seq<Cert>

    interface ICell with

        member self.Command =
            129uy

        member self.Serialize writer = 
            let rec writeCertificates (certificates: seq<Cert>) =
                if Seq.isEmpty certificates then
                    ()
                else
                    let certificate =
                        Seq.head certificates

                    writer.Write certificate.Type
                
                    certificate.Certificate.Length
                    |> uint16
                    |> writer.WriteUInt16BigEndian 

                    writer.Write certificate.Certificate

                    writeCertificates (Seq.tail certificates)

            self.Certs
            |> Seq.length
            |> uint8
            |> writer.Write

            writeCertificates self.Certs

        member self.Deserialize reader = 
            let certificatesCount = 
                reader.ReadByte()
                |> int

            let rec readCertificates certificates n = 
                if n = 0 then
                    certificates
                else
                    let certificate = { 
                        Cert.Type = reader.ReadByte()
                        Cert.Certificate = reader.ReadBigEndianUInt16() |> int |> reader.ReadBytes
                    }

                    readCertificates (certificates @ [certificate]) (n-1)

            self.Certs <-
                readCertificates List.empty certificatesCount