namespace NOnion.Directory

open System


type HiddenServiceSecondLayerDescriptorDocument =
    {
        EncryptedPayload: Option<byte[]>
    }

    static member Empty =
        {
            HiddenServiceSecondLayerDescriptorDocument.EncryptedPayload = None
        }

    static member Parse(stringToParse: string) =
        let lines = stringToParse.Split '\n' |> MutableQueue<string>

        let rec readBlock(state: string) =
            let line = lines.Dequeue()

            if line.StartsWith "-----END" then
                state + line
            else
                readBlock(state + line)

        let rec innerParse state =

            let words = lines.Peek().Split ' ' |> MutableQueue<string>

            let newState =
                match words.Dequeue() with
                | "encrypted" ->
                    lines.Dequeue() |> ignore<string>

                    let payloadString = readBlock String.Empty

                    { state with
                        HiddenServiceSecondLayerDescriptorDocument.EncryptedPayload = payloadString.Replace("-----BEGIN MESSAGE-----","").Replace("-----END MESSAGE-----","") |> Convert.FromBase64String |> Some
                    }
                | _ ->
                    lines.Dequeue() |> ignore<string>
                    state

            if lines.Count > 0 then
                innerParse newState
            else
                newState

        innerParse HiddenServiceSecondLayerDescriptorDocument.Empty
