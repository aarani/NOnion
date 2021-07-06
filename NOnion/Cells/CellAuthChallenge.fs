namespace NOnion.Cells

open NOnion
open NOnion.Extensions.BinaryIOExtensions

type CellAuthChallenge () =

    [<DefaultValue>]
    val mutable Challenge: array<byte>
    [<DefaultValue>]
    val mutable Methods: seq<uint16>
    
    interface ICell with

        member self.Command =
            130uy

        member self.Serialize writer = 
            writer.Write self.Challenge

            let rec writeMethods (methods: seq<uint16>) =
                if Seq.isEmpty methods then
                    ()
                else
                    methods
                    |> Seq.head
                    |> writer.WriteUInt16BigEndian

                    writeMethods (Seq.tail methods)

            self.Methods
            |> Seq.length
            |> uint16
            |> writer.WriteUInt16BigEndian

            writeMethods self.Methods

        member self.Deserialize reader = 
            self.Challenge <- 
                reader.ReadBytes Constants.ChallangeLength
            let methodsCount = 
                reader.ReadBigEndianUInt16()
                |> int

            let rec readMethod methods n = 
                if n = 0 then
                    methods
                else
                    readMethod (methods @ [reader.ReadBigEndianUInt16()]) (n-1)

            self.Methods <-
                readMethod [] methodsCount