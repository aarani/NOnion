namespace NOnion.Utility

open System

open NOnion
open DateTimeUtils

module HSUtility =
    let getTimePeriod (now: DateTime) (hsDirInterval: int) =
        let nowInMinutes =
            let validAfterSinceEpoch =
                now |> DateTimeUtils.GetTimeSpanSinceEpoch

            validAfterSinceEpoch
                .Subtract(
                    Constants.RotationTimeOffset
                )
                .TotalMinutes |> int

        nowInMinutes / hsDirInterval

    let getStartTimeOfCurrentSRVProtocolRun (now: DateTime) (votingInterval: TimeSpan) =
        
        let totalRounds = 2u * 12u
        let unixNow = ToUnixTimestamp(now)
        let votingIntervalInSec = votingInterval.TotalSeconds |> uint
        let currRoundSlot =  (unixNow / votingIntervalInSec) % totalRounds
        let timeElapsedSinceStartOfRun = currRoundSlot * votingIntervalInSec

        unixNow - timeElapsedSinceStartOfRun
        |> FromUnixTimestamp

    let getStartTimeOfNextTimePeriod (now: DateTime) (hsDirInterval: int) =
        let timePeriodNum = (getTimePeriod now hsDirInterval) + 1
        DateTime(1970,1,1,12,0,0) + TimeSpan.FromMinutes(timePeriodNum * hsDirInterval |> float)
    
    (*  
     * Return true if we are currently in the time segment between a new time
     * period and a new SRV (in the real network that happens between 12:00 and
     * 00:00 UTC). Here is a diagram showing exactly when this returns true:
     *
     *    +------------------------------------------------------------------+
     *    |                                                                  |
     *    | 00:00      12:00       00:00       12:00       00:00       12:00 |
     *    | SRV#1      TP#1        SRV#2       TP#2        SRV#3       TP#3  |
     *    |                                                                  |
     *    |  $==========|-----------$===========|-----------$===========|    |
     *    |             ^^^^^^^^^^^^            ^^^^^^^^^^^^                 |
     *    |                                                                  |
     *    +------------------------------------------------------------------+
     *)

    let inPeriodBetweenTPAndSRV (now: DateTime) (votingInterval: TimeSpan) (hsDirInterval: int) =
        let srvStartTime = getStartTimeOfCurrentSRVProtocolRun now votingInterval
        let tpStartTime = getStartTimeOfNextTimePeriod srvStartTime hsDirInterval

        not (now >= srvStartTime && now < tpStartTime)

    let encodeBase32 text =
        let quintupletToList ending (x0, x1, x2, x3, x4) =
          // RFC 4648: The Base 32 Alphabet
          let A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
    
          // RFC 4648: The "Extended Hex" Base 32 Alphabet
          // let A = "0123456789ABCDEFGHIJKLMNOPQRSTUV="
    
          let quintuplet = (int64 x0 <<< 32)
                       ||| (int64 x1 <<< 24)
                       ||| (int64 x2 <<< 16)
                       ||| (int64 x3 <<<  8)
                       ||| (int64 x4)
          let a0 = (quintuplet &&& 0xF800000000L) >>> 35 |> int
          let a1 = (quintuplet &&& 0x07C0000000L) >>> 30 |> int
          let a2 = (quintuplet &&& 0x003E000000L) >>> 25 |> int
          let a3 = (quintuplet &&& 0x0001F00000L) >>> 20 |> int
          let a4 = (quintuplet &&& 0x00000F8000L) >>> 15 |> int
          let a5 = (quintuplet &&& 0x0000007C00L) >>> 10 |> int
          let a6 = (quintuplet &&& 0x00000003E0L) >>>  5 |> int
          let a7 = (quintuplet &&& 0x000000001FL)        |> int
          match ending with
          | 1 -> [A.[a0]; A.[a1];   '=' ;   '=' ;   '=' ;   '=' ;   '=' ;   '=' ;] // 01======
          | 2 -> [A.[a0]; A.[a1]; A.[a2]; A.[a3];   '=' ;   '=' ;   '=' ;   '=' ;] // 0123====
          | 3 -> [A.[a0]; A.[a1]; A.[a2]; A.[a3]; A.[a4];   '=' ;   '=' ;   '=' ;] // 01234===
          | 4 -> [A.[a0]; A.[a1]; A.[a2]; A.[a3]; A.[a4]; A.[a5]; A.[a6];   '=' ;] // 0123456=
          | _ -> [A.[a0]; A.[a1]; A.[a2]; A.[a3]; A.[a4]; A.[a5]; A.[a6]; A.[a7];] // 01234567
    
        let rec parse result input =
          match input with
          | x0 :: x1 :: x2 :: x3 :: x4 :: tail -> parse (result @ quintupletToList 5 (x0, x1, x2, x3, x4)) tail
          | x0 :: x1 :: x2 :: x3 :: []         -> result @ quintupletToList 4 (x0,  x1,  x2,  x3, 0uy)
          | x0 :: x1 :: x2 :: []               -> result @ quintupletToList 3 (x0,  x1,  x2, 0uy, 0uy)
          | x0 :: x1 :: []                     -> result @ quintupletToList 2 (x0,  x1, 0uy, 0uy, 0uy)
          | x0 :: []                           -> result @ quintupletToList 1 (x0, 0uy, 0uy, 0uy, 0uy)
          | []                                 -> result
      
        (text:string)
        |> System.Text.Encoding.UTF8.GetBytes
        |> Array.toList
        |> parse []
        |> List.toArray
        |> System.String.Concat
    
    
    
    /// Decodes a Base32 string to a UTF8 string
    let decodeBase32 text = 
        if (text:string).Length % 8 <> 0 then [||] else
          // RFC 4648: The Base 32 alphabet
          let A = [for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" -> c]
                  |> List.mapi (fun i a -> a, i)
                  |> Map.ofList
    
          // RFC 4648: The "Extended Hex" Base 32 alphabet
          // let A = [for c in "0123456789ABCDEFGHIJKLMNOPQRSTUV=" -> c]
          //         |> List.mapi (fun i a -> a, i)
          //         |> Map.ofList
                      
          let (.@) (m: Map<char, int>) key = try m.[System.Char.ToUpper key] |> int64 with _ -> 0L
        
          let octetToList ending (a0, a1, a2, a3, a4, a5, a6, a7) =
            let octet = (A.@ a0 &&& 0x1FL <<< 35)
                    ||| (A.@ a1 &&& 0x1FL <<< 30)
                    ||| (A.@ a2 &&& 0x1FL <<< 25)
                    ||| (A.@ a3 &&& 0x1FL <<< 20)
                    ||| (A.@ a4 &&& 0x1FL <<< 15)
                    ||| (A.@ a5 &&& 0x1FL <<< 10)
                    ||| (A.@ a6 &&& 0x1FL <<<  5)
                    ||| (A.@ a7 &&& 0x1FL)
            let x0 = (octet &&& 0xFF00000000L) >>> 32 |> byte
            let x1 = (octet &&& 0x00FF000000L) >>> 24 |> byte
            let x2 = (octet &&& 0x0000FF0000L) >>> 16 |> byte
            let x3 = (octet &&& 0x000000FF00L) >>>  8 |> byte
            let x4 = (octet &&& 0x00000000FFL)        |> byte
            match ending with
            | 2 -> [x0;]
            | 4 -> [x0; x1;]
            | 5 -> [x0; x1; x2;]
            | 7 -> [x0; x1; x2; x3;]
            | _ -> [x0; x1; x2; x3; x4;]
        
          let rec parse result input =
            match input with
            | a0 :: a1 :: '=':: '=':: '=':: '=':: '=':: '=':: _    -> result @ octetToList 2 (a0, a1,'=','=','=','=','=','=')
            | a0 :: a1 :: a2 :: a3 :: '=':: '=':: '=':: '=':: _    -> result @ octetToList 4 (a0, a1, a2, a3,'=','=','=','=')
            | a0 :: a1 :: a2 :: a3 :: a4 :: '=':: '=':: '=':: _    -> result @ octetToList 5 (a0, a1, a2, a3, a4,'=','=','=')
            | a0 :: a1 :: a2 :: a3 :: a4 :: a5 :: a6 :: '=':: _    -> result @ octetToList 7 (a0, a1, a2, a3, a4, a5, a6,'=')
            | a0 :: a1 :: a2 :: a3 :: a4 :: a5 :: a6 :: a7 :: tail -> parse (result @ octetToList 8 (a0, a1, a2, a3, a4, a5, a6, a7)) tail
            | _                                                    -> result
    
          [for c in text -> c]
          |> parse []
          |> List.toArray
    

    let getPublicKeyFromUrl (url: string) =
        let bytes = url.Split('.').[0] |> decodeBase32
        
        assert (bytes.Length = 32 + 2 + 1)

        bytes.[0..31]