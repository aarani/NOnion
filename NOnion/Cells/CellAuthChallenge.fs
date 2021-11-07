namespace NOnion.Cells

open System.IO

open NOnion
open NOnion.Utility.BinaryIO

type CellAuthChallenge =
    {
        Challenge: array<byte>
        Methods: seq<uint16>
    }

    static member Deserialize(reader: BinaryReader) =

        let rec readMethod methods n =
            if n = 0 then
                methods
            else
                readMethod(methods @ [ ReadBigEndianUInt16 reader ]) (n - 1)

        let challenge = reader.ReadBytes Constants.ChallangeLength
        let methodsCount = ReadBigEndianUInt16 reader |> int
        let methods = readMethod [] methodsCount

        {
            Challenge = challenge
            Methods = methods
        }
        :> ICell

    interface ICell with

        member __.Command = 130uy

        member self.Serialize writer =

            let rec writeMethods(methods: seq<uint16>) =
                match Seq.tryHead methods with
                | None -> ()
                | Some method ->
                    WriteUInt16BigEndian writer method
                    methods |> Seq.tail |> writeMethods

            writer.Write self.Challenge
            self.Methods |> Seq.length |> uint16 |> WriteUInt16BigEndian writer
            writeMethods self.Methods
