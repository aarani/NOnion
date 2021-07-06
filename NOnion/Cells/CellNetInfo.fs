namespace NOnion.Cells

open NOnion
open NOnion.Extensions.BinaryIOExtensions


type RouterAddress = {
    Type: byte
    Value: array<byte>
}

type CellNetInfo () =

    [<DefaultValue>]
    val mutable Time: uint32
    [<DefaultValue>]
    val mutable MyAddresses: seq<RouterAddress>
    [<DefaultValue>]
    val mutable OtherAddress: RouterAddress

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

        member self.Deserialize reader = 
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

            self.Time <-
                reader.ReadBigEndianUInt32 ()
            self.OtherAddress <- 
                readAddress ()

            let myAddressesCount = 
                reader.ReadByte ()
            self.MyAddresses <-
                readAddresses List.Empty myAddressesCount