// An implementation for https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt
namespace NOnion.Utility

open System.IO

open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Crypto.Parameters

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

type CertType =
    // https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt#L162
    | IntroPointAuthKeySignedByDescriptorSigningKey = 9uy
    | ShortTermDescriptorSigningKeyByBlindedPublicKey = 8uy
    | IntroPointEncKeySignedByDescriptorSigningKey = 0x0Buy

type Certificate =
    {
        Version: byte
        Type: CertType
        ExpirationDate: uint
        CertKeyType: byte
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

        let tempBeforeVerify =
            {
                Version = reader.ReadByte()
                Type =
                    reader.ReadByte()
                    |> LanguagePrimitives.EnumOfValue<byte, CertType>
                ExpirationDate = BinaryIO.ReadBigEndianUInt32 reader
                CertKeyType = reader.ReadByte()
                CertifiedKey = reader.ReadBytes 32
                Extensions =
                    readExtensions (reader.ReadByte() |> int) List.empty
                Signature = reader.ReadBytes 64
            }

        match tempBeforeVerify.TryGetSignedWithEd25519Key() with
        | Some signedByKey ->
            let verifier = Ed25519Signer()
            verifier.Init(false, Ed25519PublicKeyParameters(signedByKey, 0))
            let tmpBytes = tempBeforeVerify.ToBytes(true)
            verifier.BlockUpdate(tmpBytes, 0, tmpBytes.Length)

            if not(verifier.VerifySignature(tempBeforeVerify.Signature)) then
                failwith "Invalid certificate"
        | None -> ()

        tempBeforeVerify


    member self.ToBytes(ignoreSig: bool) =
        Array.concat
            [
                Array.singleton self.Version
                Array.singleton(self.Type |> byte)
                IntegerSerialization.FromUInt32ToBigEndianByteArray
                    self.ExpirationDate
                Array.singleton self.CertKeyType
                self.CertifiedKey
                Array.singleton(self.Extensions.Length |> byte)
                self.Extensions
                |> Seq.collect(fun ext -> ext.ToBytes())
                |> Seq.toArray
                if ignoreSig then
                    Array.empty
                else
                    self.Signature
            ]
