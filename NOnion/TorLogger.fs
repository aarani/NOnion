namespace NOnion

open System

module TorLogger =
    let mutable LoggerOpt: Option<Action<string>> = None

    let Init(loggingFunc: Action<string>) =
        LoggerOpt <- Some loggingFunc

    let Log(msg: string) =
        let msgWithDateTime = sprintf "[%s] %s" (DateTime.UtcNow.ToString()) msg

        match LoggerOpt with
        | None -> ()
        | Some logger -> logger.Invoke msgWithDateTime
