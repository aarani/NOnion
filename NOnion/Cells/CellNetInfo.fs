namespace NOnion.Cells

open System.IO

open NOnion.Utility.BinaryIO

type RouterAddress =
    {
        Type: byte
        Value: array<byte>
    }

(*
    If version 2 or higher is negotiated, each party sends the other a
    NETINFO cell.  The cell's payload is:

       TIME       (Timestamp)                     [4 bytes]
       OTHERADDR  (Other OR's address)            [variable]
          ATYPE   (Address type)                  [1 byte]
          ALEN    (Adress length)                 [1 byte]
          AVAL    (Address value in NBO)          [ALEN bytes]
       NMYADDR    (Number of this OR's addresses) [1 byte]
         NMYADDR times:
           ATYPE   (Address type)                 [1 byte]
           ALEN    (Adress length)                [1 byte]
           AVAL    (Address value in NBO))        [ALEN bytes]

    Recognized address types (ATYPE) are:

      [04] IPv4.
      [06] IPv6.

    ALEN MUST be 4 when ATYPE is 0x04 (IPv4) and 16 when ATYPE is 0x06
    (IPv6).  If the ALEN value is wrong for the given ATYPE value, then
    the provided address should be ignored.

    The timestamp is a big-endian unsigned integer number of seconds
    since the Unix epoch. Implementations MUST ignore unexpected bytes
    at the end of the cell.  Clients SHOULD send "0" as their timestamp, to
    avoid fingerprinting.

    Implementations MAY use the timestamp value to help decide if their
    clocks are skewed.  Initiators MAY use "other OR's address" to help
    learn which address their connections may be originating from, if they do
    not know it; and to learn whether the peer will treat the current
    connection as canonical.  Implementations SHOULD NOT trust these
    values unconditionally, especially when they come from non-authorities,
    since the other party can lie about the time or IP addresses it sees.

    Initiators SHOULD use "this OR's address" to make sure
    that they have connected to another OR at its canonical address.
    (See 5.3.1 below.)
*)

type CellNetInfo =
    {
        Time: uint32
        MyAddresses: seq<RouterAddress>
        OtherAddress: RouterAddress
    }

    static member Deserialize (reader: BinaryReader) =

        let readAddress () : RouterAddress =
            {
                RouterAddress.Type = reader.ReadByte ()
                Value = reader.ReadByte () |> int |> reader.ReadBytes
            }

        let rec readAddresses (addresses) (n) =
            if n = 0uy then
                addresses
            else
                readAddresses (addresses @ [ readAddress () ]) (n - 1uy)

        let time = ReadBigEndianUInt32 reader
        let otherAddress = readAddress ()
        let myAddressesCount = reader.ReadByte ()
        let myAddresses = readAddresses List.Empty myAddressesCount

        {
            Time = time
            MyAddresses = myAddresses
            OtherAddress = otherAddress
        }
        :> ICell

    interface ICell with

        member __.Command = 8uy

        member self.Serialize writer =

            let writeAddress (addr: RouterAddress) =
                writer.Write addr.Type
                addr.Value.Length |> byte |> writer.Write
                writer.Write addr.Value

            let rec writeAddresses (addresses: seq<RouterAddress>) =
                match Seq.tryHead addresses with
                | None -> ()
                | Some addr ->
                    writeAddress addr
                    writeAddresses (Seq.tail addresses)

            WriteUInt32BigEndian writer self.Time
            writeAddress self.OtherAddress
            self.MyAddresses |> Seq.length |> byte |> writer.Write
            writeAddresses self.MyAddresses
