namespace NOnion

open System
open System.Runtime.ExceptionServices

module FSharpUtil =
    //Implementation copied from https://github.com/nblockchain/geewallet/blob/master/src/GWallet.Backend/FSharpUtil.fs
    let ReRaise (ex: Exception) : Exception =
        (ExceptionDispatchInfo.Capture ex).Throw ()
        failwith "Should be unreachable"
        ex
