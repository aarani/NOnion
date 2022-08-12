namespace NOnion.Directory

open System
open System.Net

open NOnion
open NOnion.Network
open NOnion.Http
open NOnion.Utility

type RouterType =
    | Normal
    | Guard
    | Directory

type TorDirectory =
    private
        {
            mutable NetworkStatus: NetworkStatusDocument
            mutable ServerDescriptors: Map<string, ServerDescriptorEntry>
        }

    member private self.IsLive() =
        let now = DateTime.UtcNow

        self.NetworkStatus.GetValidAfter() < now
        && self.NetworkStatus.GetValidUntil() > now

    member private self.GetRandomDirectorySource() =
        let directorySourceOpt =
            self.NetworkStatus.Routers
            |> Seq.filter(fun elem ->
                elem.DirectoryPort.IsSome && elem.DirectoryPort.Value <> 0
            )
            |> SeqUtils.TakeRandom 1
            |> Seq.tryHead

        match directorySourceOpt with
        | Some directorySource -> directorySource
        | None -> failwith "Couldn't find suitable directory source."

    member private self.ConvertToCircuitNodeDetail
        (entry: ServerDescriptorEntry)
        =
        let fingerprintBytes = Hex.ToByteArray(entry.Fingerprint.Value)
        let nTorOnionKeyBytes = Base64Util.FromString(entry.NTorOnionKey.Value)

        let endpoint =
            IPEndPoint(
                IPAddress.Parse(entry.Address.Value),
                entry.OnionRouterPort.Value
            )

        CircuitNodeDetail.Create(endpoint, nTorOnionKeyBytes, fingerprintBytes)

    member self.GetRouter(filter: RouterType) =
        async {
            do! self.UpdateConsensusIfNotLive()

            let rec getRandomRouter() =
                async {
                    let descriptor =
                        let randomServerOpt =
                            self.NetworkStatus.Routers
                            |> match filter with
                               | Normal -> Seq.ofList
                               | Directory ->
                                   Seq.filter(fun router ->
                                       router.DirectoryPort.IsSome
                                       && router.DirectoryPort.Value > 0
                                   )
                               | Guard ->
                                   Seq.filter(fun router ->
                                       Seq.contains "Guard" router.Flags
                                   )
                            |> SeqUtils.TakeRandom 1
                            |> Seq.tryHead

                        match randomServerOpt with
                        | Some randomServer ->
                            self.GetDescriptorByIdentity(
                                randomServer.GetIdentity()
                            )
                        | None -> failwith "Couldn't find suitable router"

                    if descriptor.Hibernating
                       || descriptor.NTorOnionKey.IsNone
                       || descriptor.Fingerprint.IsNone then
                        return! getRandomRouter()
                    else
                        return descriptor
                }

            let! randomDescriptor = getRandomRouter()

            let endpoint =
                IPEndPoint(
                    IPAddress.Parse(randomDescriptor.Address.Value),
                    randomDescriptor.OnionRouterPort.Value
                )

            return (endpoint, self.ConvertToCircuitNodeDetail randomDescriptor)
        }

    member self.GetRouterAsync(filter: RouterType) =
        self.GetRouter filter |> Async.StartAsTask

    member self.GetCircuitNodeDetailByIdentity(identity: string) =
        self.GetDescriptorByIdentity identity |> self.ConvertToCircuitNodeDetail

    member private self.UpdateConsensusIfNotLive() =
        async {
            if self.IsLive() then
                TorLogger.Log
                    "TorDirectory: no need to get the consensus document"

                return ()
            else
                TorLogger.Log "TorDirectory: Updating consensus document..."

                let directoryRouter = self.GetRandomDirectorySource()

                use! guard =
                    TorGuard.NewClient(
                        IPEndPoint(
                            IPAddress.Parse(directoryRouter.IP.Value),
                            directoryRouter.OnionRouterPort.Value
                        )
                    )

                let circuit = TorCircuit(guard)
                let stream = TorStream(circuit)

                (*
                 * We always use FastCreate authentication because privacy is not important for mono-hop
                 * directory browsing, this removes the need of checking descriptors and making sure they
                 * are no more than one week old (according to spec, routers must accept outdated keys
                 * until 1 week after key update).
                 *)
                do! circuit.Create CircuitNodeDetail.FastCreate |> Async.Ignore

                do! stream.ConnectToDirectory() |> Async.Ignore

                let httpClient = TorHttpClient(stream, directoryRouter.IP.Value)

                let! response =
                    httpClient.GetAsString
                        "/tor/status-vote/current/consensus"
                        false

                self.NetworkStatus <- NetworkStatusDocument.Parse response
        }

    static member Bootstrap(nodeEndPoint: IPEndPoint) =
        async {
            use! guard = TorGuard.NewClient(nodeEndPoint)
            let circuit = TorCircuit(guard)
            do! circuit.Create(CircuitNodeDetail.FastCreate) |> Async.Ignore

            let consensusStream = TorStream(circuit)
            do! consensusStream.ConnectToDirectory() |> Async.Ignore

            let consensusHttpClient =
                TorHttpClient(consensusStream, nodeEndPoint.Address.ToString())

            let! consensusStr =
                consensusHttpClient.GetAsString
                    "/tor/status-vote/current/consensus"
                    false

            let descriptorsStream = TorStream(circuit)
            do! descriptorsStream.ConnectToDirectory() |> Async.Ignore

            let descriptorsHttpClient =
                TorHttpClient(descriptorsStream, "127.0.0.1")

            let! descriptorsStr =
                descriptorsHttpClient.GetAsString "/tor/server/all" false

            let routers =
                (ServerDescriptorsDocument.Parse descriptorsStr)
                    .Routers

            let serverDescriptors =
                routers
                |> Seq.map(fun router ->
                    (router.Fingerprint.Value
                     |> Hex.ToByteArray
                     |> Convert.ToBase64String,
                     router)
                )
                |> Map.ofSeq

            return
                {
                    TorDirectory.NetworkStatus =
                        NetworkStatusDocument.Parse consensusStr
                    ServerDescriptors = serverDescriptors
                }
        }


    member self.GetLiveNetworkStatus() =
        async {
            do! self.UpdateConsensusIfNotLive()
            return self.NetworkStatus
        }

    member self.GetDescriptorByIdentity(b64Identity: string) =
        self.ServerDescriptors.[b64Identity]

    static member BootstrapAsync(nodeEndPoint: IPEndPoint) =
        TorDirectory.Bootstrap nodeEndPoint |> Async.StartAsTask
