namespace NOnion.Cells

open System.IO

open NOnion
open NOnion.Extensions.BinaryIOExtensions

type CellAuthChallenge (challenge: array<byte>, methods: seq<uint16>) =

    member self.Challenge = challenge

    member self.Methods = methods

    static member Deserialize (reader : BinaryReader) =
        
        let challenge = reader.ReadBytes Constants.ChallangeLength

        let methodsCount = 
            reader.ReadBigEndianUInt16()
            |> int

        let rec readMethod methods n = 
            if n = 0 then
                methods
            else
                readMethod (methods @ [reader.ReadBigEndianUInt16()]) (n-1)

        let methods =
            readMethod [] methodsCount

        CellAuthChallenge (challenge, methods) :> ICell
    
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