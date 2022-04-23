namespace NOnion.Directory

open System


type HiddenServiceFirstLayerDescriptorDocument =
    {
        Version: Option<int>
        Lifetime: Option<int>
        SigningKeyCert: Option<string>
        RevisionCounter: Option<int64>
        EncryptedPayload: Option<byte[]>
        Signature: Option<string>
    }

    static member Empty =
        {
            HiddenServiceFirstLayerDescriptorDocument.Version = None
            Lifetime = None
            SigningKeyCert = None
            RevisionCounter = None
            EncryptedPayload = None
            Signature = None
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

            let readInteger() =
                words.Dequeue() |> int

            let readLong() =
                words.Dequeue() |> Convert.ToInt64

            let readRestAsString() =
                words.ToArray() |> String.concat " "

            let newState =
                match words.Dequeue() with
                | "signature" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.Signature = readRestAsString() |> Some
                    }
                | "hs-descriptor" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.Version = readInteger() |> Some
                    }
                | "descriptor-lifetime" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.Lifetime = readInteger() |> Some
                    }
                | "descriptor-signing-key-cert" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.SigningKeyCert = readBlock String.Empty |> Some
                    }
                | "revision-counter" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.RevisionCounter = readLong () |> Some
                    }
                | "superencrypted" ->
                    lines.Dequeue() |> ignore<string>

                    let payloadString = readBlock String.Empty

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.EncryptedPayload = payloadString.Replace("-----BEGIN MESSAGE-----","").Replace("-----END MESSAGE-----","") |> Convert.FromBase64String |> Some
                    }
                | _ ->
                    lines.Dequeue() |> ignore<string>
                    state

            if lines.Count > 0 then
                innerParse newState
            else
                newState

        innerParse HiddenServiceFirstLayerDescriptorDocument.Empty
