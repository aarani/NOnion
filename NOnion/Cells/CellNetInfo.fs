namespace NOnion.Cells

open System.IO

open NOnion
open NOnion.Extensions.BinaryIOExtensions

type RouterAddress = {
    Type: byte
    Value: array<byte>
}

type CellNetInfo (time: uint32, myAddresses: seq<RouterAddress>, otherAddress: RouterAddress) =

    member self.Time = time
    member self.MyAddresses = myAddresses
    member self.OtherAddress = otherAddress
            
    static member Deserialize (reader : BinaryReader) =

        let readAddress (): RouterAddress =
            {
                RouterAddress.Type = reader.ReadByte()
                Value = reader.ReadByte () |> int |> reader.ReadBytes
            }

        let rec readAddresses (addresses) (n) =
            if n = 0uy then
                addresses
            else
                readAddresses (addresses @ [readAddress()]) (n-1uy)

        let time = reader.ReadBigEndianUInt32 ()
        let otherAddress = readAddress ()
        let myAddressesCount = reader.ReadByte ()
        let myAddresses = readAddresses List.Empty myAddressesCount
        CellNetInfo (time, myAddresses, otherAddress) :> ICell

    interface ICell with

        member self.Command =
            8uy

        member self.Serialize writer = 
            let writeAddress (addr: RouterAddress) =
                writer.Write addr.Type
            
                addr.Value.Length 
                |> byte
                |> writer.Write 
            
                writer.Write addr.Value

            let rec writeAddresses (addresses: seq<RouterAddress>) =
                match Seq.tryHead addresses with
                | None -> 
                    ()
                | Some addr -> 
                    writeAddress addr
                    writeAddresses (Seq.tail addresses)

            writer.WriteUInt32BigEndian self.Time

            writeAddress self.OtherAddress
        
            self.MyAddresses
            |> Seq.length
            |> byte
            |> writer.Write 
            writeAddresses self.MyAddresses