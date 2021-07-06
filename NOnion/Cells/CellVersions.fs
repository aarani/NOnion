namespace NOnion.Cells

open NOnion
open NOnion.Extensions.BinaryIOExtensions


type CellVersions ()=
    inherit Cell ()

    [<DefaultValue>]
    val mutable Versions: seq<uint16>

    override self.Command =
        7uy

    override self.Serialize writer = 
        let rec writeVersions (versions: seq<uint16>) =
            match Seq.tryHead versions with 
            | None -> ()
            | Some version ->
                writer.WriteUInt16BigEndian version

                writeVersions (Seq.tail versions)

        writeVersions self.Versions

    override self.Deserialize reader = 
        let rec readVersions versions = 
            if (reader.BaseStream.Length - reader.BaseStream.Position) % 2L <> 0L then
                failwith "Version packet payload is invalid, payload length should be divisable by 2"

            if reader.BaseStream.Length = reader.BaseStream.Position then
                versions
            else
                readVersions (versions @ [reader.ReadBigEndianUInt16()])

        self.Versions <-
            readVersions List.empty