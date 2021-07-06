namespace NOnion.Extensions

open System

open NOnion.Extensions.IntegerExtensions

module BinaryIOExtensions = 
    type System.IO.BinaryWriter with
        member self.WriteUInt16BigEndian (num: uint16): unit= 
            num.ToBigEndianByteArray ()
            |> self.Write
        member self.WriteUInt32BigEndian (num: uint32): unit= 
            num.ToBigEndianByteArray ()
            |> self.Write

    type System.IO.BinaryReader with
        member self.ReadBigEndianUInt16 (): uint16 =
            sizeof<uint16>
            |> self.ReadBytes
            |> UInt16.FromBigEndianByteArray
        member self.ReadBigEndianUInt32 (): uint32 =
            sizeof<uint32>
            |> self.ReadBytes
            |> UInt32.FromBigEndianByteArray