namespace NOnion.Utility

module EventUtils =
    let FilterByKey (keyToFind: uint16) (source: IEvent<uint16 * _>) =
        let keyFilter (keyToFind: uint16) (key, value) =
            if key = keyToFind then
                Some value
            else
                None

        source |> Event.choose (keyFilter keyToFind)
