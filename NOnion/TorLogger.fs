namespace NOnion

open System

module TorLogger =
    let mutable LoggerOpt: Option<Action<string>> = None

    let Init(loggingFunc: Action<string>) =
        LoggerOpt <- Some loggingFunc

    let Log(msg: string) =
        match LoggerOpt with
        | None -> ()
        | Some logger -> logger.Invoke(msg)
