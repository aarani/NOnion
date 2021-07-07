namespace NOnion.Cells

open System.IO

open NOnion
open NOnion.Extensions

type CellAuthChallenge =
    {
        Challenge: array<byte>
        Methods: seq<uint16>
    }

    static member Deserialize (reader: BinaryReader) =

        let challenge = reader.ReadBytes Constants.ChallangeLength

        let methodsCount =
            BinaryIOExtensions.BinaryReader.ReadBigEndianUInt16 reader |> int

        let rec readMethod methods n =
            if n = 0 then
                methods
            else
                readMethod
                    (methods
                     @ [
                         BinaryIOExtensions.BinaryReader.ReadBigEndianUInt16
                             reader
                     ])
                    (n - 1)

        let methods = readMethod [] methodsCount

        {
            Challenge = challenge
            Methods = methods
        }
        :> ICell

    interface ICell with

        member __.Command = 130uy

        member self.Serialize writer =
            writer.Write self.Challenge

            let rec writeMethods (methods: seq<uint16>) =
                if Seq.isEmpty methods then
                    ()
                else
                    methods
                    |> Seq.head
                    |> BinaryIOExtensions.BinaryWriter.WriteUInt16BigEndian
                        writer

                    writeMethods (Seq.tail methods)

            self.Methods
            |> Seq.length
            |> uint16
            |> BinaryIOExtensions.BinaryWriter.WriteUInt16BigEndian writer

            writeMethods self.Methods
