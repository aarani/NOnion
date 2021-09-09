namespace NOnion.Cells.Relay

open System.IO

open NOnion
open NOnion.Cells
open NOnion.Utility

type RelayIntroduce =
    {
        AuthKey: RelayIntroAuthKey
        Extensions: List<RelayIntroExtension>
        EncryptedData: array<byte>
    }

    static member FromBytes (reader: BinaryReader) =
        let legacyKeyId = reader.ReadBytes 20

        if legacyKeyId |> Array.forall (fun byte -> byte = 0uy) then
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

        let encryptedData =
            reader.BaseStream.Length - reader.BaseStream.Position
            |> int
            |> reader.ReadBytes

        {
            AuthKey = authKey
            Extensions = extensions
            EncryptedData = encryptedData
        }

    member self.ToBytes () =
        Array.concat [ Array.zeroCreate 20
                       self.AuthKey.ToBytes ()
                       self.Extensions.Length |> byte |> Array.singleton
                       self.Extensions
                       |> List.map (fun ext -> ext.ToBytes ())
                       |> Array.concat
                       self.EncryptedData ]
