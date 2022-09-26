// An implementation for https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt
namespace NOnion.Utility

open System.IO

type CertificateExtension =
    {
        Type: int
        Flags: byte
        Data: array<byte>
    }

type Certificate =
    {
        Version: int
        Type: int
        ExpirationDate: uint
        CertKeyType: int
        CertifiedKey: array<byte>
        Extensions: List<CertificateExtension>
        Signature: array<byte>
    }

    // https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt#L175
    member self.TryGetSignedWithEd25519Key() =
        let signedWithExtenstionTypeNum = 4

        self.Extensions
        |> Seq.tryFind(fun ext -> ext.Type = signedWithExtenstionTypeNum)
        |> Option.map(fun ext -> ext.Data)


    static member Deserialize(reader: BinaryReader) =
        let rec readExtensions
            (remainingExtsCount: int)
            (state: List<CertificateExtension>)
            =
            if remainingExtsCount = 0 then
                state
            else
                let dataLength = BinaryIO.ReadBigEndianUInt16 reader |> int

                let newExtension =
                    {
                        CertificateExtension.Type = reader.ReadByte() |> int
                        Flags = reader.ReadByte()
                        Data = reader.ReadBytes dataLength
                    }

                readExtensions
                    (remainingExtsCount - 1)
                    (state @ [ newExtension ])

        {
            Version = reader.ReadByte() |> int
            Type = reader.ReadByte() |> int
            ExpirationDate = BinaryIO.ReadBigEndianUInt32 reader
            CertKeyType = reader.ReadByte() |> int
            CertifiedKey = reader.ReadBytes 32
            Extensions = readExtensions (reader.ReadByte() |> int) List.empty
            Signature = reader.ReadBytes 64
        }
