// An implementation for https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt
namespace NOnion.Utility

open System.IO

type CertificateExtensionType =
    // https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt#L175
    | SignedWithEd25519Key = 4uy

type CertificateExtension =
    {
        Type: CertificateExtensionType
        Flags: byte
        Data: array<byte>
    }

    static member Deserialize(reader: BinaryReader) =
        let dataLength = BinaryIO.ReadBigEndianUInt16 reader |> int

        {
            CertificateExtension.Type =
                reader.ReadByte()
                |> LanguagePrimitives.EnumOfValue<byte, CertificateExtensionType>
            Flags = reader.ReadByte()
            Data = reader.ReadBytes dataLength
        }

    member self.ToBytes() =
        Array.concat
            [
                self.Data.Length
                |> uint16
                |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                Array.singleton(byte self.Type)
                Array.singleton self.Flags
                self.Data
            ]

type CertKeyType =
    // https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt#L162
    | IntroPointAuthKeySignedByDescriptorSigningKey = 9uy

type Certificate =
    {
        Version: byte
        Type: byte
        ExpirationDate: uint
        CertKeyType: CertKeyType
        CertifiedKey: array<byte>
        Extensions: List<CertificateExtension>
        Signature: array<byte>
    }

    member self.TryGetSignedWithEd25519Key() =
        self.Extensions
        |> Seq.tryFind(fun ext ->
            ext.Type = CertificateExtensionType.SignedWithEd25519Key
        )
        |> Option.map(fun ext -> ext.Data)

    static member Deserialize(reader: BinaryReader) =
        let rec readExtensions
            (remainingExtsCount: int)
            (state: List<CertificateExtension>)
            =
            if remainingExtsCount = 0 then
                state
            else
                readExtensions
                    (remainingExtsCount - 1)
                    (CertificateExtension.Deserialize reader :: state)

        {
            Version = reader.ReadByte()
            Type = reader.ReadByte()
            ExpirationDate = BinaryIO.ReadBigEndianUInt32 reader
            CertKeyType =
                reader.ReadByte()
                |> LanguagePrimitives.EnumOfValue<byte, CertKeyType>
            CertifiedKey = reader.ReadBytes 32
            Extensions = readExtensions (reader.ReadByte() |> int) List.empty
            Signature = reader.ReadBytes 64
        }

    member self.ToBytes() =
        Array.concat
            [
                Array.singleton self.Version
                Array.singleton self.Type
                IntegerSerialization.FromUInt32ToBigEndianByteArray
                    self.ExpirationDate
                Array.singleton(self.CertKeyType |> byte)
                self.CertifiedKey
                Array.singleton(self.Extensions.Length |> byte)
                self.Extensions
                |> Seq.map(fun ext -> ext.ToBytes())
                |> Seq.concat
                |> Seq.toArray
                self.Signature
            ]
