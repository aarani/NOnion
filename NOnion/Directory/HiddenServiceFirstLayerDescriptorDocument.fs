namespace NOnion.Directory

open System
open System.Text

open NOnion.Utility
open System.IO
open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Crypto.Parameters

type HiddenServiceFirstLayerDescriptorDocument =
    {
        Version: Option<int>
        Lifetime: Option<int>
        SigningKeyCert: Option<array<byte>>
        RevisionCounter: Option<int64>
        EncryptedPayload: Option<array<byte>>
        Signature: Option<array<byte>>
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
                    let signature = readRestAsString() |> Base64Util.FromString

                    match state.SigningKeyCert with
                    | Some keyCert ->
                        use memStream = new MemoryStream(keyCert)
                        use reader = new BinaryReader(memStream)
                        let cert = Certificate.Deserialize reader

                        let signer = Ed25519Signer()

                        signer.Init(
                            false,
                            Ed25519PublicKeyParameters(cert.CertifiedKey, 0)
                        )
                        //FIXME: reserializing for verification is not a good idea
                        // order of keywords might be different instead we need to
                        // remove the "signature" line and verify the rest
                        let currentStateInBytes =
                            "Tor onion service descriptor sig v3"
                            + state.ToString()
                            |> Encoding.ASCII.GetBytes

                        signer.BlockUpdate(
                            currentStateInBytes,
                            0,
                            currentStateInBytes.Length
                        )

                        if not(signer.VerifySignature(signature)) then
                            failwith "oops!"
                    | None -> ()

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.Signature =
                            Some signature
                    }
                | "hs-descriptor" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.Version =
                            readInteger() |> Some
                    }
                | "descriptor-lifetime" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.Lifetime =
                            readInteger() |> Some
                    }
                | "descriptor-signing-key-cert" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.SigningKeyCert =
                            (readBlock String.Empty)
                                .Replace("-----BEGIN ED25519 CERT-----", "")
                                .Replace("-----END ED25519 CERT-----", "")
                            |> Convert.FromBase64String
                            |> Some
                    }
                | "revision-counter" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.RevisionCounter =
                            readLong() |> Some
                    }
                | "superencrypted" ->
                    lines.Dequeue() |> ignore<string>

                    let payloadString = readBlock String.Empty

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.EncryptedPayload =
                            payloadString
                                .Replace("-----BEGIN MESSAGE-----", "")
                                .Replace("-----END MESSAGE-----", "")
                            |> Convert.FromBase64String
                            |> Some
                    }
                | _ ->
                    lines.Dequeue() |> ignore<string>
                    state

            if lines.Count > 0 then
                innerParse newState
            else
                newState

        innerParse HiddenServiceFirstLayerDescriptorDocument.Empty

    override self.ToString() =
        let writeByteArray data =
            let dataInString = data |> Convert.ToBase64String

            let chunkedData =
                dataInString.ToCharArray()
                |> Array.chunkBySize 64
                |> Array.map String

            String.Join("\n", chunkedData)


        let strBuilder = StringBuilder()

        let appendLine str =
            strBuilder.Append(sprintf "%s\n" str)

        match self.Version with
        | Some version ->
            appendLine(sprintf "hs-descriptor %i" version)
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing version"

        match self.Lifetime with
        | Some lifeTime ->
            appendLine(sprintf "descriptor-lifetime %i" lifeTime)
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing lifetime"

        match self.SigningKeyCert with
        | Some keyCert ->
            appendLine "descriptor-signing-key-cert" |> ignore<StringBuilder>
            appendLine "-----BEGIN ED25519 CERT-----" |> ignore<StringBuilder>
            appendLine(writeByteArray keyCert) |> ignore<StringBuilder>
            appendLine "-----END ED25519 CERT-----" |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing signing key cert"

        match self.RevisionCounter with
        | Some counter ->
            appendLine(sprintf "revision-counter %i" counter)
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing revision-counter"

        match self.EncryptedPayload with
        | Some encrypted ->
            appendLine "superencrypted" |> ignore<StringBuilder>
            appendLine "-----BEGIN MESSAGE-----" |> ignore<StringBuilder>
            appendLine(writeByteArray encrypted) |> ignore<StringBuilder>
            appendLine "-----END MESSAGE-----" |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing payload"

        match self.Signature with
        | Some signature when signature.Length > 0 ->
            appendLine(
                sprintf "signature %s" (Base64Util.ToStringNoPad signature)
            )
            |> ignore<StringBuilder>
        | _ -> ()

        strBuilder.ToString()
