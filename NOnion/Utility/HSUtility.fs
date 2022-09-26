namespace NOnion.Utility

open System

open NOnion
open DateTimeUtils

module HSUtility =
    let GetTimePeriod (now: DateTime) (hsDirInterval: int) =
        let nowInMinutes =
            let validAfterSinceEpoch = now |> GetTimeSpanSinceEpoch

            validAfterSinceEpoch
                .Subtract(
                    Constants.RotationTimeOffset
                )
                .TotalMinutes
            |> int

        nowInMinutes / hsDirInterval

    let private GetStartTimeOfCurrentSRVProtocolRun
        (now: DateTime)
        (votingInterval: TimeSpan)
        =

        let totalRounds =
            Constants.SharedRandomNPhases * Constants.SharedRandomNRounds

        let unixNow = ToUnixTimestamp(now)
        let votingIntervalInSec = votingInterval.TotalSeconds |> uint
        let currRoundSlot = (unixNow / votingIntervalInSec) % totalRounds
        let timeElapsedSinceStartOfRun = currRoundSlot * votingIntervalInSec

        unixNow - timeElapsedSinceStartOfRun |> FromUnixTimestamp

    let private GetStartTimeOfNextTimePeriod
        (now: DateTime)
        (hsDirInterval: int)
        =
        let timePeriodNum = (GetTimePeriod now hsDirInterval) + 1

        DateTime(1970, 1, 1, 12, 0, 0)
        + TimeSpan.FromMinutes(timePeriodNum * hsDirInterval |> float)

    (*
     * Ported from https://github.com/torproject/tor/blob/aa28535f671152cfae763c254569a89317a91341/src/feature/hs/hs_common.c#L987
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

    let InPeriodBetweenTPAndSRV
        (now: DateTime)
        (votingInterval: TimeSpan)
        (hsDirInterval: int)
        =
        let srvStartTime =
            GetStartTimeOfCurrentSRVProtocolRun now votingInterval

        let tpStartTime =
            GetStartTimeOfNextTimePeriod srvStartTime hsDirInterval

        not(now >= srvStartTime && now < tpStartTime)

    // https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/rend-spec-v3.txt#L2161
    let GetPublicKeyFromUrl(url: string) =
        //Remove .onion suffix and decode
        let keyBytesOpt =
            url.Split('.') |> Seq.tryHead |> Option.map Base32Util.DecodeBase32

        let expectedOnionUrlLength = 32 + 2 + 1

        match keyBytesOpt with
        | Some keyBytes when keyBytes.Length = expectedOnionUrlLength ->
            keyBytes.[0..31]
        | _ -> failwith "Invalid onion service url"
