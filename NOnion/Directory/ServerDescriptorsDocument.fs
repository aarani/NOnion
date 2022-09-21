// Types in this file are marked as obsolete and this file has self-references which cause pointless warnings
#nowarn "44"

namespace NOnion.Directory

open System
open System.Text

open Org.BouncyCastle.Crypto.Digests

open NOnion.Utility

type internal MutableQueue<'T> = System.Collections.Generic.Queue<'T>

[<Obsolete("Use micro-descriptors instead")>]
type ServerDescriptorEntry =
    {
        Nickname: Option<string>
        Address: Option<string>
        OnionRouterPort: Option<int>
        SocksPort: Option<int>
        DirectoryPort: Option<int>
        IdentityEd25519: Option<string>
        MasterKeyEd25519: Option<string>
        Bandwidth: Option<string>
        Platform: Option<string>
        Published: Option<DateTime>
        Fingerprint: Option<string>
        Hibernating: bool
        Uptime: Option<int>
        OnionKey: Option<string>
        OnionKeyCrossCert: Option<string>
        NTorOnionKey: Option<string>
        NTorOnionKeyCrossCert: Option<int * string>
        SigningKey: Option<string>
        Accept: Option<string>
        Reject: Option<string>
        IpV6Policy: Option<string>
        OverloadGeneral: Option<string>
        RouterSigEd25519: Option<string>
        RouterSignature: Option<string>
        Contact: Option<string>
        BridgeDistributionRequest: Option<string>
        Family: Option<string>
        ReadHistory: Option<string>
        WriteHistory: Option<string>
        EventDNS: Option<bool>
        CachesExtraInfo: Option<string>
        ExtraInfoDigest: Option<string>
        HiddenServiceDir: bool
        Protocols: Option<string>
        AllowSingleHopExits: bool
        OnionRouterAddress: Option<string>
        TunnelledDirServer: bool
        Proto: Option<string>
        Digest: Option<string>
    }

    static member Empty =
        {
            Nickname = None
            Address = None
            OnionRouterPort = None
            SocksPort = None
            DirectoryPort = None
            IdentityEd25519 = None
            MasterKeyEd25519 = None
            Bandwidth = None
            Platform = None
            Published = None
            Fingerprint = None
            Hibernating = false
            Uptime = None
            OnionKey = None
            OnionKeyCrossCert = None
            NTorOnionKey = None
            NTorOnionKeyCrossCert = None
            SigningKey = None
            Accept = None
            Reject = None
            IpV6Policy = None
            OverloadGeneral = None
            RouterSigEd25519 = None
            RouterSignature = None
            Contact = None
            BridgeDistributionRequest = None
            Family = None
            ReadHistory = None
            WriteHistory = None
            EventDNS = None
            CachesExtraInfo = None
            ExtraInfoDigest = None
            HiddenServiceDir = false
            Protocols = None
            AllowSingleHopExits = false
            OnionRouterAddress = None
            TunnelledDirServer = false
            Proto = None
            Digest = None
        }

    static member Parse(lines: MutableQueue<string>) =
        let history = StringBuilder()

        let dequeueLineAndAddToHistory() =
            let line = lines.Dequeue()
            history.Append(sprintf "%s\n" line) |> ignore<StringBuilder>
            line

        let rec innerParse state =
            let rec readBlock(state: string) =
                let line = dequeueLineAndAddToHistory()

                if line.StartsWith "-----END" then
                    state + line
                else
                    readBlock(state + line)

            if lines.Count = 0 then
                state
            else
                let nextLine = lines.Peek()

                let words = nextLine.Split ' ' |> MutableQueue<string>

                let readDateTime() =
                    String.concat " " [ words.Dequeue(); words.Dequeue() ]
                    |> DateTime.Parse

                let readInt() =
                    words.Dequeue() |> int

                let readRestAsString() =
                    words.ToArray() |> String.concat " "

                let readWord() =
                    words.Dequeue()

                match words.Dequeue() with
                | "router" when state.Nickname = None ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Nickname = readWord() |> Some
                            Address = readWord() |> Some
                            OnionRouterPort = readInt() |> Some
                            SocksPort = readInt() |> Some
                            DirectoryPort = readInt() |> Some
                        }
                | "identity-ed25519" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            IdentityEd25519 = readBlock String.Empty |> Some
                        }
                | "master-key-ed25519" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            MasterKeyEd25519 = readRestAsString() |> Some
                        }
                | "bandwidth" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Bandwidth = readRestAsString() |> Some
                        }
                | "platform" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Platform = readRestAsString() |> Some
                        }
                | "published" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Published = readDateTime() |> Some
                        }
                | "fingerprint" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Fingerprint =
                                (readRestAsString()).Replace(" ", String.Empty)
                                |> Some
                        }
                | "hibernating" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Hibernating = readInt() |> Convert.ToBoolean
                        }
                | "uptime" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Uptime = readInt() |> Some
                        }
                | "onion-key" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            OnionKey = readBlock String.Empty |> Some
                        }
                | "onion-key-crosscert" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            OnionKeyCrossCert = readBlock String.Empty |> Some
                        }
                | "ntor-onion-key" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            NTorOnionKey = readRestAsString() |> Some
                        }
                | "ntor-onion-key-crosscert" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            NTorOnionKeyCrossCert =
                                (readInt(), readBlock String.Empty) |> Some
                        }
                | "signing-key" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            SigningKey = readBlock String.Empty |> Some
                        }
                | "accept" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Accept = readRestAsString() |> Some
                        }
                | "reject" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Reject = readRestAsString() |> Some
                        }
                | "ipv6-policy" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            IpV6Policy = readRestAsString() |> Some
                        }
                | "overload-general" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            OverloadGeneral = readRestAsString() |> Some
                        }
                | "router-sig-ed25519" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            RouterSigEd25519 = readRestAsString() |> Some
                        }
                | "contact" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Contact = readRestAsString() |> Some
                        }
                | "bridge-distribution-request" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            BridgeDistributionRequest =
                                readRestAsString() |> Some
                        }
                | "family" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Family = readRestAsString() |> Some
                        }
                | "read-history" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            ReadHistory = readRestAsString() |> Some
                        }
                | "write-history" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            WriteHistory = readRestAsString() |> Some
                        }
                | "eventdns" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            EventDNS = readInt() |> Convert.ToBoolean |> Some
                        }
                | "extra-info-digest" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            ExtraInfoDigest = readRestAsString() |> Some
                        }
                | "hidden-service-dir" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            HiddenServiceDir = true
                        }
                | "protocols" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Protocols = readRestAsString() |> Some
                        }
                | "allow-single-hop-exits" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            AllowSingleHopExits = true
                        }
                | "or-address" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            OnionRouterAddress = readRestAsString() |> Some
                        }
                | "tunnelled-dir-server" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            TunnelledDirServer = true
                        }
                | "proto" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Proto = readRestAsString() |> Some
                        }
                | "router-signature" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    let documentToDigestInBytes =
                        history.ToString() |> Encoding.ASCII.GetBytes

                    let digestEngine = Sha1Digest()

                    let documentDigest =
                        Array.zeroCreate<byte>(digestEngine.GetDigestSize())

                    digestEngine.BlockUpdate(
                        documentToDigestInBytes,
                        0,
                        documentToDigestInBytes.Length
                    )

                    digestEngine.DoFinal(documentDigest, 0) |> ignore<int>

                    let signature = readBlock String.Empty

                    // router-signature is always the final item in the descriptor
                    { state with
                        RouterSignature = Some signature
                        Digest =
                            Base64Util.EncodeNoPaddding documentDigest |> Some
                    }
                | "router" when state.Nickname <> None ->
                    failwith
                        "Can't parse server descriptors, new router item appeared before router-signature!"
                | _ ->
                    //Ignore possible unknown items (future-proofness)
                    dequeueLineAndAddToHistory() |> ignore<string>
                    innerParse state

        innerParse ServerDescriptorEntry.Empty

[<Obsolete("Use micro-descriptors instead")>]
type ServerDescriptorsDocument =
    {
        Routers: List<ServerDescriptorEntry>
    }

    static member Empty =
        {
            ServerDescriptorsDocument.Routers = List.empty
        }

    static member Parse(stringToParse: string) =
        let lines = stringToParse.Split '\n' |> MutableQueue<string>

        let rec innerParse state =
            let words = lines.Peek().Split ' ' |> MutableQueue<string>

            let newState =
                match words.Dequeue() with
                | "router" ->
                    { state with
                        Routers =
                            ServerDescriptorEntry.Parse lines :: state.Routers
                    }
                | _ ->
                    lines.Dequeue() |> ignore<string>
                    state

            if lines.Count > 0 then
                innerParse newState
            else
                newState

        innerParse ServerDescriptorsDocument.Empty
