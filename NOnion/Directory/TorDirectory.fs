namespace NOnion.Directory

open System
open System.IO
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

    member private self.GetServerDescriptor (fingerprint: string) =
        async {
            match self.ServerDescriptors.TryFind fingerprint with
            | Some (descriptor) ->
                return descriptor
            | None ->
                let directoryRouter = self.GetRandomDirectorySource ()
                
                use! guard =
                    TorGuard.NewClient (
                        IPEndPoint (
                            IPAddress.Parse (directoryRouter.Address.Value),
                            directoryRouter.OnionRouterPort.Value
                        )
                    )
                
                let circuit = TorCircuit (guard)
                let stream = TorStream (circuit)
                
                do! circuit.Create (CircuitNodeDetail.FastCreate) |> Async.Ignore
                do! stream.ConnectToDirectory () |> Async.Ignore
                
                let httpClient =
                    new TorHttpClient (stream, directoryRouter.Address.Value)
                
                let! response =
                    httpClient.GetAsString
                        (sprintf "/tor/server/fp/%s" (fingerprint |> Convert.FromBase64String |> Hex.FromByteArray))
                        false
                
                let serverDescriptor = 
                    (ServerDescriptorsDocument.Parse response)
                        .Routers
                        .Head

                self.ServerDescriptors <-
                    self.ServerDescriptors
                    |> Map.add fingerprint serverDescriptor

                return 
                    serverDescriptor
        }

    
    member private self.GetRandomCircuit (numHops: int) =
        async {
            let routers =
                self.NetworkStatus.Routers
                |> SeqUtils.TakeRandom numHops

            let getNodeDetails (router: seq<RouterStatusEntry>) (details: seq<CircuitNodeDetail>)=
                async {
                    let! descriptor =
                        self.GetServerDescriptor(router.Identity.Value)

                    let fingerprintBytes = Hex.ToByteArray(server.Fingerprint.Value);
                    let nTorOnionKeyBytes = Base64Util.FromString(server.NTorOnionKey.Value);
                    let endpoint = 
                        IPEndPoint (
                            IPAddress.Parse (directoryRouter.Address.Value),
                            directoryRouter.OnionRouterPort.Value
                        )
                    
                    return
                        endpoint,
                        CircuitNodeDetail.Create endpoint nTorOnionKeyBytes fingerprintBytes
                }

            
        }
        

    member private self.UpdateConsensusIfNotLive () =
        async {
            if self.IsLive () then
                return ()

            let directoryRouter = self.GetRandomDirectorySource ()

            use! guard =
                TorGuard.NewClient (
                    IPEndPoint (
                        IPAddress.Parse (directoryRouter.Address.Value),
                        directoryRouter.OnionRouterPort.Value
                    )
                )

            let circuit = TorCircuit (guard)
            let stream = TorStream (circuit)

            do! circuit.Create (CircuitNodeDetail.FastCreate) |> Async.Ignore
            do! stream.ConnectToDirectory () |> Async.Ignore

            let httpClient =
                new TorHttpClient (stream, directoryRouter.Address.Value)

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
                new TorHttpClient (
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
                new TorHttpClient (
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
