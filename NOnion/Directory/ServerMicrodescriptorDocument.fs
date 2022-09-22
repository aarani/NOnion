namespace NOnion.Directory

open System
open System.Text

open Org.BouncyCastle.Crypto.Digests

open NOnion.Utility

type MicroDescriptorEntry =
    {
        Address: Option<string>
        OnionKey: Option<string>
        NTorOnionKey: Option<string>
        Ed25519Identity: Option<string>
        RSA1024Identity: Option<string>
        IpV4Policy: Option<string>
        IpV6Policy: Option<string>
        Family: Option<string>
        Proto: Option<string>
        Digest: Option<string>
    }

    static member Empty =
        {
            Address = None
            OnionKey = None
            NTorOnionKey = None
            Ed25519Identity = None
            RSA1024Identity = None
            IpV4Policy = None
            IpV6Policy = None
            Family = None
            Proto = None
            Digest = None
        }

    static member ParseMany(stringToParse: string) =
        let lines = stringToParse.Split '\n' |> MutableQueue<string>

        let history = StringBuilder()

        let dequeueLineAndAddToHistory() =
            let line = lines.Dequeue()
            history.Append(sprintf "%s\n" line) |> ignore<StringBuilder>
            line

        let clearHistory() =
            history.Clear() |> ignore<StringBuilder>

        let getDigestFromHistory() =
            let documentToDigestInBytes =
                history.ToString() |> Encoding.ASCII.GetBytes

            clearHistory()

            let digestEngine = Sha256Digest()

            let documentDigest =
                Array.zeroCreate<byte>(digestEngine.GetDigestSize())

            digestEngine.BlockUpdate(
                documentToDigestInBytes,
                0,
                documentToDigestInBytes.Length
            )

            digestEngine.DoFinal(documentDigest, 0) |> ignore<int>

            documentDigest |> Base64Util.EncodeNoPadding

        let rec innerParse
            (state: MicroDescriptorEntry)
            (previousEntries: List<MicroDescriptorEntry>)
            =
            let rec readBlock(state: string) =
                let line = sprintf "%s\n" (dequeueLineAndAddToHistory())

                if line.StartsWith "-----END" then
                    state + line
                else
                    readBlock(state + line)

            if lines.Count = 0 then
                let finishedEntry =
                    { state with
                        Digest = getDigestFromHistory() |> Some
                    }

                finishedEntry :: previousEntries
            else
                let nextLine = lines.Peek()

                let words = nextLine.Split ' ' |> MutableQueue<string>

                let readRestAsString() =
                    words.ToArray() |> String.concat " "

                let readWord() =
                    words.Dequeue()

                match words.Dequeue() with
                | "onion-key" when state.OnionKey.IsNone ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            OnionKey = readBlock String.Empty |> Some
                        }
                        previousEntries
                | "onion-key" when not state.OnionKey.IsNone ->
                    let finishedEntry =
                        { state with
                            Digest = getDigestFromHistory() |> Some
                        }

                    innerParse
                        MicroDescriptorEntry.Empty
                        (finishedEntry :: previousEntries)
                | "ntor-onion-key" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            NTorOnionKey = readRestAsString() |> Some
                        }
                        previousEntries
                | "id" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    match readWord() with
                    | "rsa1024" ->
                        innerParse
                            { state with
                                RSA1024Identity = readWord() |> Some
                            }
                            previousEntries
                    | "ed25519" ->
                        innerParse
                            { state with
                                Ed25519Identity = readWord() |> Some
                            }
                            previousEntries
                    | _ ->
                        //Implementations MUST ignore "id" lines with unrecognized key-types in place of "rsa1024" or "ed25519"
                        innerParse state previousEntries
                | "p" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            IpV4Policy = readRestAsString() |> Some
                        }
                        previousEntries
                | "p6" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            IpV6Policy = readRestAsString() |> Some
                        }
                        previousEntries
                | "family" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Family = readRestAsString() |> Some
                        }
                        previousEntries
                | "pr" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Proto = readRestAsString() |> Some
                        }
                        previousEntries
                | _ ->
                    //Ignore possible unknown items (future-proofness)
                    dequeueLineAndAddToHistory() |> ignore<string>
                    innerParse state previousEntries

        innerParse MicroDescriptorEntry.Empty List.empty
