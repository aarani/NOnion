namespace NOnion.Utility

open System

module ObservableUtils =
    let FilterByKey (keyToFind: uint16) (source: IObservable<uint16 * _>) =
        let keyFilter (keyToFind: uint16) (key, value) =
            if key = keyToFind then
                Some value
            else
                None

        source |> Observable.choose (keyFilter keyToFind)
