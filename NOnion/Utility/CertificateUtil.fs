namespace NOnion.Utility


open System.IO

type CertificateExtension =
    {
        Type: int
        Flags: byte
        Data: byte[]
    }

type Certificate =
    {
        Version: int
        Type: int
        ExpirationDate: uint
        CertKeyType: int
        CertifiedKey: byte[]
        Extensions: List<CertificateExtension>
        Signature: byte[]
    }

    member self.GetSignedWithEd25519Key () =
        (self.Extensions
        |> Seq.find (fun ext -> ext.Type = 4)).Data


    static member Deserialize(reader: BinaryReader) =
        let rec readExtensions (n: byte) (state: List<CertificateExtension>) =
            if n = 0uy then
                state
            else
                let length = BinaryIO.ReadBigEndianUInt16  reader |> int
                state @ [
                    {
                        CertificateExtension.Type = reader.ReadByte () |> int
                        Flags = reader.ReadByte()
                        Data = reader.ReadBytes length
                    }
                ]
        
        {
            Version = reader.ReadByte() |> int
            Type = reader.ReadByte() |> int
            ExpirationDate = BinaryIO.ReadBigEndianUInt32 reader
            CertKeyType = reader.ReadByte() |> int
            CertifiedKey = reader.ReadBytes 32
            Extensions = readExtensions (reader.ReadByte()) List.empty
            Signature = reader.ReadBytes 64
        }