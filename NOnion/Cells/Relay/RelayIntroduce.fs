namespace NOnion.Cells.Relay

open System.IO

open NOnion
open NOnion.Cells
open NOnion.Utility

type RelayIntroduce =
    {
        AuthKey: RelayIntroAuthKey
        Extensions: List<RelayIntroExtension>
        ClientPublicKey: array<byte>
        EncryptedData: array<byte>
        Mac: array<byte>
    }

    static member FromBytes (reader: BinaryReader) =
        let legacyKeyId = reader.ReadBytes 20

        if not (legacyKeyId |> Array.forall (fun byte -> byte = 0uy)) then
            failwith "Legacy key id should be all zeroes"

        let authKey = RelayIntroAuthKey.FromBytes reader

        let extensions =
            let extensionCount = reader.ReadByte ()

            let rec readExtensionsList state n =
                if n = 0uy then
                    state
                else
                    readExtensionsList
                        (state
                         @ List.singleton (RelayIntroExtension.FromBytes reader))
                        (n - 1uy)

            readExtensionsList List.empty extensionCount

        let remainingDataSize =
            reader.BaseStream.Length - reader.BaseStream.Position |> int

        let encryptedDataSize =
            remainingDataSize
            - authKey.MacLength
            - Constants.NTorPublicKeyLength

        let publicKey = reader.ReadBytes Constants.NTorPublicKeyLength

        let encryptedData = encryptedDataSize |> reader.ReadBytes

        let mac = reader.ReadBytes authKey.MacLength

        {
            AuthKey = authKey
            Extensions = extensions
            ClientPublicKey = publicKey
            EncryptedData = encryptedData
            Mac = mac
        }

    member self.ToBytes () =
        Array.concat
            [
                Array.zeroCreate 20
                self.AuthKey.ToBytes ()
                self.Extensions.Length |> byte |> Array.singleton
                self.Extensions
                |> List.map (fun ext -> ext.ToBytes ())
                |> Array.concat
                self.EncryptedData
            ]
