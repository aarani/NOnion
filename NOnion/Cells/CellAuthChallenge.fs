namespace NOnion.Cells

open System.IO

open NOnion
open NOnion.Utility.BinaryIO

(*
    An AUTH_CHALLENGE cell is a variable-length cell with the following
    fields:

        Challenge [32 octets]
        N_Methods [2 octets]
        Methods   [2 * N_Methods octets]

    It is sent from the responder to the initiator. Initiators MUST
    ignore unexpected bytes at the end of the cell.  Responders MUST
    generate every challenge independently using a strong RNG or PRNG.
*)

type CellAuthChallenge =
    {
        Challenge: array<byte>
        Methods: seq<uint16>
    }

    static member Deserialize (reader: BinaryReader) =

        let rec readMethod methods n =
            if n = 0 then
                methods
            else
                readMethod (methods @ [ ReadBigEndianUInt16 reader ]) (n - 1)

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

            let rec writeMethods (methods: seq<uint16>) =
                match Seq.tryHead methods with
                | None -> ()
                | Some method ->
                    WriteUInt16BigEndian writer method
                    methods |> Seq.tail |> writeMethods

            writer.Write self.Challenge
            self.Methods |> Seq.length |> uint16 |> WriteUInt16BigEndian writer
            writeMethods self.Methods
