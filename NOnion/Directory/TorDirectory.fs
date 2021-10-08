namespace NOnion.Directory

open System
open System.Net

open NOnion.Network
open NOnion.Http
open NOnion.Utility

type TorDirectory =
    private
        {
            mutable NetworkStatus: NetworkStatusDocument
            mutable ServerDescriptors: Map<string, ServerDescriptorEntry>
        }

    member private self.IsLive () =
        let now = DateTime.UtcNow

        self.NetworkStatus.GetValidAfter () < now
        && self.NetworkStatus.GetValidUntil () > now

    member private self.GetRandomDirectorySource () =
        self.NetworkStatus.Routers
        |> Seq.filter (fun elem ->
            elem.DirectoryPort.IsSome && elem.DirectoryPort.Value <> 0
        )
        |> SeqUtils.TakeRandom 1
        |> Seq.head

    member private self.ConvertToCircuitNodeDetail
        (entry: ServerDescriptorEntry)
        =
        let fingerprintBytes = Hex.ToByteArray (entry.Fingerprint.Value)
        let nTorOnionKeyBytes = Base64Util.FromString (entry.NTorOnionKey.Value)

        let endpoint =
            IPEndPoint (
                IPAddress.Parse (entry.Address.Value),
                entry.OnionRouterPort.Value
            )

        CircuitNodeDetail.Create (endpoint, nTorOnionKeyBytes, fingerprintBytes)

    member self.GetRouter (shouldBeDirectory: bool) =
        async {
            do! self.UpdateConsensusIfNotLive ()

            let rec getRandomRouter () =
                async {
                    let! descriptor =
                        if shouldBeDirectory then
                            self.NetworkStatus.Routers
                            |> Seq.filter (fun router ->
                                router.DirectoryPort.IsSome
                                && router.DirectoryPort.Value > 0
                            )
                        else
                            self.NetworkStatus.Routers |> Seq.ofList
                        |> SeqUtils.TakeRandom 1
                        |> Seq.head
                        |> self.GetServerDescriptor

                    if descriptor.Hibernating
                       || descriptor.NTorOnionKey.IsNone
                       || descriptor.Fingerprint.IsNone then
                        return! getRandomRouter ()
                    else
                        return descriptor
                }

            let! randomDescriptor = getRandomRouter ()
            return self.ConvertToCircuitNodeDetail randomDescriptor
        }

    member self.GetRouterAsync (shouldBeDirectory: bool) =
        self.GetRouter shouldBeDirectory |> Async.StartAsTask

    member private self.GetServerDescriptor
        (routerEntry: RouterStatusEntry)
        : Async<ServerDescriptorEntry> =
        async {
            let fingerprint = routerEntry.GetIdentity ()

            match self.ServerDescriptors.TryFind fingerprint with
            | Some descriptor -> return descriptor
            | None ->
                let directoryRouter = self.GetRandomDirectorySource ()

                use! guard =
                    TorGuard.NewClient (
                        IPEndPoint (
                            IPAddress.Parse (directoryRouter.IP.Value),
                            directoryRouter.OnionRouterPort.Value
                        )
                    )

                let circuit = TorCircuit (guard)
                let stream = TorStream (circuit)

                do!
                    circuit.Create (CircuitNodeDetail.FastCreate)
                    |> Async.Ignore

                do! stream.ConnectToDirectory () |> Async.Ignore

                let httpClient =
                    TorHttpClient (stream, directoryRouter.IP.Value)

                let! response =
                    httpClient.GetAsString
                        (sprintf
                            "/tor/server/fp/%s"
                            (fingerprint
                             |> Convert.FromBase64String
                             |> Hex.FromByteArray))
                        false

                let serverDescriptor =
                    (ServerDescriptorsDocument.Parse response)
                        .Routers
                        .Head

                self.ServerDescriptors <-
                    self.ServerDescriptors
                    |> Map.add fingerprint serverDescriptor

                return serverDescriptor
        }

    member private self.UpdateConsensusIfNotLive () =
        async {
            if self.IsLive () then
                return ()
            else
                let directoryRouter = self.GetRandomDirectorySource ()

                use! guard =
                    TorGuard.NewClient (
                        IPEndPoint (
                            IPAddress.Parse (directoryRouter.IP.Value),
                            directoryRouter.OnionRouterPort.Value
                        )
                    )

                let circuit = TorCircuit (guard)
                let stream = TorStream (circuit)

                (*
                 * We use normal NTor authentication if we have any cached server descriptor for the node,
                 * because even though our descriptor might be out of date according to spec the router
                 * must accept any outdated keys until 1 week after key-update.
                 *)
                do!
                    match directoryRouter.GetIdentity ()
                          |> self.ServerDescriptors.TryFind with
                    | None -> CircuitNodeDetail.FastCreate
                    | Some serverDescriptor ->
                        self.ConvertToCircuitNodeDetail serverDescriptor
                    |> circuit.Create
                    |> Async.Ignore

                do! stream.ConnectToDirectory () |> Async.Ignore

                let httpClient =
                    TorHttpClient (stream, directoryRouter.IP.Value)

                let! response =
                    httpClient.GetAsString
                        "/tor/status-vote/current/consensus"
                        false

                self.NetworkStatus <- NetworkStatusDocument.Parse response
        }

    static member Bootstrap (nodeEndPoint: IPEndPoint) =
        async {
            use! guard = TorGuard.NewClient (nodeEndPoint)
            let circuit = TorCircuit (guard)
            do! circuit.Create (CircuitNodeDetail.FastCreate) |> Async.Ignore

            let consensusStream = TorStream (circuit)
            do! consensusStream.ConnectToDirectory () |> Async.Ignore

            let consensusHttpClient =
                TorHttpClient (
                    consensusStream,
                    nodeEndPoint.Address.ToString ()
                )

            let! consensusStr =
                consensusHttpClient.GetAsString
                    "/tor/status-vote/current/consensus"
                    false

            let serverDescriptorsStream = TorStream (circuit)
            do! serverDescriptorsStream.ConnectToDirectory () |> Async.Ignore

            let serverDescriptorsHttpClient =
                TorHttpClient (
                    serverDescriptorsStream,
                    nodeEndPoint.Address.ToString ()
                )

            let! serverDescriptorsStr =
                serverDescriptorsHttpClient.GetAsString "/tor/server/all" false

            return
                {
                    TorDirectory.NetworkStatus =
                        NetworkStatusDocument.Parse consensusStr
                    ServerDescriptors =
                        (ServerDescriptorsDocument.Parse serverDescriptorsStr)
                            .Routers
                        |> Seq.map (fun router ->
                            (router.Fingerprint.Value.Replace (" ", "")
                             |> Hex.ToByteArray
                             |> Convert.ToBase64String,
                             router)
                        )
                        |> Map.ofSeq
                }
        }


    member self.GetLiveNetworkStatus () =
        async {
            do! self.UpdateConsensusIfNotLive ()
            return self.NetworkStatus
        }

    static member BootstrapAsync (nodeEndPoint: IPEndPoint) =
        TorDirectory.Bootstrap nodeEndPoint |> Async.StartAsTask
