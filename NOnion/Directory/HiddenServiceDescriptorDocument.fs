namespace NOnion.Directory

open System


type IntroductionPointEntry =
    {
        OnionKey: Option<byte[]>
        AuthKey: Option<byte[]>
        EncKey: Option<byte[]>
        EncKeyCert: Option<byte[]>
        LinkSpecifiers: Option<byte[]>
    }

    static member Empty =
        {
            IntroductionPointEntry.OnionKey = None
            AuthKey = None
            EncKey = None
            EncKeyCert = None
            LinkSpecifiers = None
        }

    static member Parse(lines: MutableQueue<string>) =
        let rec innerParse state =
            if lines.Count = 0 then
                state
            else
                let words = lines.Peek().Split ' ' |> MutableQueue<string>

                let rec readBlock(state: string) =
                    let line = lines.Dequeue()

                    if line.StartsWith "-----END" then
                        state
                    else
                        readBlock(state + line)

                let readWord() =
                    words.Dequeue()

                match words.Dequeue() with
                | "introduction-point" when state.LinkSpecifiers = None ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            LinkSpecifiers = readWord() |> Convert.FromBase64String |> Some
                        }
                | "introduction-point" when state.LinkSpecifiers <> None -> state
                | "onion-key" ->
                    lines.Dequeue() |> ignore<string>
                    readWord () |> ignore<string>
                    innerParse
                        { state with
                            OnionKey = readWord() |> Convert.FromBase64String |> Some
                        }
                | "enc-key" ->
                    lines.Dequeue() |> ignore<string>
                    readWord () |> ignore<string>
                    innerParse
                        { state with
                            EncKey = readWord() |> Convert.FromBase64String |> Some
                        }
                | "auth-key" ->
                    lines.Dequeue() |> ignore<string>
                    //get rid of begin
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            AuthKey =
                                readBlock String.Empty |> Convert.FromBase64String |> Some
                        }
                | "enc-key-cert" ->
                    lines.Dequeue() |> ignore<string>
                    //get rid of begin
                    lines.Dequeue() |> ignore<string>


                    innerParse
                        { state with
                            EncKeyCert =
                                readBlock String.Empty |> Convert.FromBase64String |> Some
                        }
                
                | _ -> state

        innerParse IntroductionPointEntry.Empty

type HiddenServiceDescriptorDocument =
    {
        Create2Formats: Option<int>
        IsSingleOnionService: bool

        IntroductionPoints: List<IntroductionPointEntry>
    }

    static member Empty =
        {
            HiddenServiceDescriptorDocument.Create2Formats = None
            IsSingleOnionService = false
            
            IntroductionPoints = List.empty
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
                | "create2-formats" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceDescriptorDocument.Create2Formats = readInteger() |> Some
                    }
                | "single-onion-service" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceDescriptorDocument.IsSingleOnionService = true
                    }
                | "introduction-point" ->
                    { state with
                        IntroductionPoints =
                            state.IntroductionPoints
                            @ List.singleton(IntroductionPointEntry.Parse lines)
                    }
                | _ ->
                    lines.Dequeue() |> ignore<string>
                    state

            if lines.Count > 0 then
                innerParse newState
            else
                newState

        innerParse HiddenServiceDescriptorDocument.Empty
