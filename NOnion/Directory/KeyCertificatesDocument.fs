namespace NOnion.Directory

open System
open System.Text

open NOnion.Utility.FSharpUtil
open System.Security.Cryptography

type KeyCertificateEntry =
    {
        Version: Option<int>
        Address: Option<string>
        Fingerprint: Option<string>
        IdentityKey: Option<string>
        Published: Option<string>
        Expires: Option<string>
        SigningKey: Option<string>
        CrossCert: Option<string>
        Certification: Option<string>
    }

    static member Empty =
        {
            Version = None
            Address = None
            Fingerprint = None
            IdentityKey = None
            Published = None
            Expires = None
            SigningKey = None
            CrossCert = None
            Certification = None
        }

    static member ParseMany(stringToParse: string) =
        let lines = stringToParse.Split '\n' |> MutableQueue<string>

        let history = StringBuilder()

        let dequeueLineAndAddToHistory() =
            let line = lines.Dequeue()
            history.Append(sprintf "%s\n" line) |> ignore<StringBuilder>
            line

        let rec innerParse
            (state: KeyCertificateEntry)
            (previousEntries: List<KeyCertificateEntry>)
            =
            let rec readBlock(state: string) =
                let line = sprintf "%s\n" (dequeueLineAndAddToHistory())

                if line.StartsWith "-----END" then
                    state + line
                else
                    readBlock(state + line)

            let validate (state: KeyCertificateEntry) (history: string) =
                let pemToByteArray(pem: string) = 
                    pem
                        .Replace("-----BEGIN RSA PUBLIC KEY-----", String.Empty)
                        .Replace("-----END RSA PUBLIC KEY-----", String.Empty)
                        .Replace("\n", String.Empty)

                let identityKey = UnwrapOption state.IdentityKey "Identity key not found"
                let signingKey = UnwrapOption state.SigningKey "Signing key not found"
                let crosscert =
                    (UnwrapOption state.CrossCert "Crosscert was not founds")
                        .Replace("-----BEGIN ID SIGNATURE-----", String.Empty)
                        .Replace("-----BEGIN SIGNATURE-----", String.Empty)
                        .Replace("-----END ID SIGNATURE-----", String.Empty)
                        .Replace("-----END SIGNATURE-----", String.Empty)
                        .Replace("\n", String.Empty)
                    |> System.Convert.FromBase64String
                let identityKeyHash =
                    let sha1 = SHA1.Create()
                    let identityKeyHash =
                        sha1.ComputeHash(pemToByteArray identityKey)
                    
                    

                innerParse
                    KeyCertificateEntry.Empty
                    (state :: previousEntries)

            if lines.Count = 0 then
                state::previousEntries
            else
                let nextLine = lines.Peek()

                let words = nextLine.Split ' ' |> MutableQueue<string>

                let readRestAsString() =
                    words.ToArray() |> String.concat " "

                let readInt() =
                    words.Dequeue() |> int

                match words.Dequeue() with
                | "dir-key-certificate-version" when state.Version.IsNone ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Version = readInt () |> Some
                        }
                        previousEntries
                | "dir-key-certificate-version" when not state.Version.IsNone ->
                    failwith "Should not happen: dir-key-certificate-version seen when already initialized"
                | "dir-address" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Address = readRestAsString() |> Some
                        }
                        previousEntries
                | "fingerprint" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Fingerprint = readRestAsString() |> Some
                        }
                        previousEntries
                | "dir-identity-key" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            IdentityKey = readBlock String.Empty |> Some
                        }
                        previousEntries
                | "dir-key-published" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Published = readRestAsString() |> Some
                        }
                        previousEntries
                | "dir-key-expires" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Expires = readRestAsString() |> Some
                        }
                        previousEntries
                | "dir-signing-key" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            SigningKey = readBlock String.Empty |> Some
                        }
                        previousEntries
                | "dir-key-crosscert" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            CrossCert = readBlock String.Empty |> Some
                        }
                        previousEntries
                | "dir-key-certification" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    let historyBeforeCertification = 
                        history.ToString()

                    validate 
                        { state with
                            Certification = readBlock String.Empty |> Some
                        }
                        historyBeforeCertification
                | _ ->
                    //Ignore possible unknown items (future-proofness)
                    dequeueLineAndAddToHistory() |> ignore<string>
                    innerParse state previousEntries

        innerParse KeyCertificateEntry.Empty List.empty
