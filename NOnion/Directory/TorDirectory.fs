namespace NOnion.Directory

open System
open System.Net
open System.Text

open NOnion
open NOnion.Crypto
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
            mutable ServerDescriptors: Map<string, MicroDescriptorEntry>
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
        | None ->
            failwith
                "TorDirectory::GetRandomDirectorySource: couldn't find suitable directory source."

    member self.GetMicroDescriptorByIdentity
        (identity: string)
        : Async<MicroDescriptorEntry> =
        async {
            let! networkStatus = self.GetLiveNetworkStatus()

            let routerConsensusEntryOpt =
                networkStatus.Routers
                |> List.tryFind(fun router -> router.Identity.Value = identity)

            match routerConsensusEntryOpt with
            | None ->
                return
                    failwith
                        "TorDirectory::GetMicroDescriptorByIdentity: router was not in the latest consensus"
            | Some routerConsensusEntry ->
                if self.ServerDescriptors
                   |> Map.containsKey
                       routerConsensusEntry.MicroDescriptorDigest.Value then
                    return
                        self.ServerDescriptors.[routerConsensusEntry.MicroDescriptorDigest.Value]
                else
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
                    do!
                        circuit.Create CircuitNodeDetail.FastCreate
                        |> Async.Ignore

                    do! stream.ConnectToDirectory() |> Async.Ignore

                    let httpClient =
                        TorHttpClient(stream, directoryRouter.IP.Value)

                    let! response =
                        httpClient.GetAsString
                            (sprintf
                                "/tor/micro/d/%s"
                                routerConsensusEntry.MicroDescriptorDigest.Value)
                            false

                    let parsedDescriptorOpt =
                        MicroDescriptorEntry.ParseMany response
                        |> Seq.tryExactlyOne

                    match parsedDescriptorOpt with
                    | None ->
                        return
                            failwith
                                "BUG: can't get microdescriptor, Parse returned no item or more than one"
                    | Some parsedDescriptor ->
                        self.ServerDescriptors <-
                            self.ServerDescriptors
                            |> Map.add
                                routerConsensusEntry.MicroDescriptorDigest.Value
                                parsedDescriptor

                        return parsedDescriptor
        }

    member private self.GetRouterDetailByIdentity(identity: string) =
        async {
            let! networkStatus = self.GetLiveNetworkStatus()

            let routerEntryOpt =
                networkStatus.Routers
                |> List.tryFind(fun router -> router.Identity.Value = identity)

            match routerEntryOpt with
            | None ->
                return
                    failwith
                        "TorDirectory::GetRouterDetailByIdentity: router was not in the latest consensus"
            | Some routerEntry ->
                let! descriptor = self.GetMicroDescriptorByIdentity identity

                let fingerprintBytes =
                    Base64Util.FromString(routerEntry.GetIdentity())

                let nTorOnionKeyBytes =
                    Base64Util.FromString(descriptor.NTorOnionKey.Value)

                let endpoint =
                    IPEndPoint(
                        IPAddress.Parse(routerEntry.IP.Value),
                        routerEntry.OnionRouterPort.Value
                    )

                return
                    endpoint,
                    CircuitNodeDetail.Create(
                        endpoint,
                        nTorOnionKeyBytes,
                        fingerprintBytes
                    )
        }


    member self.GetRouter(filter: RouterType) =
        async {
            do! self.UpdateConsensusIfNotLive()

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
                return!
                    randomServer.GetIdentity() |> self.GetRouterDetailByIdentity
            | None -> return failwith "Couldn't find suitable router"
        }

    member self.GetRouterAsync(filter: RouterType) =
        self.GetRouter filter |> Async.StartAsTask

    member self.GetCircuitNodeDetailByIdentity(identity: string) =
        async {
            let! _endpoint, circuitNodeDetail =
                self.GetRouterDetailByIdentity identity

            return circuitNodeDetail
        }

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
                        "/tor/status-vote/current/consensus-microdesc"
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
                    "/tor/status-vote/current/consensus-microdesc"
                    false

            let networkStatus = NetworkStatusDocument.Parse consensusStr

            let downloadDescriptorsForChunk(digestsChunk: array<string>) =
                async {
                    let descriptorsStream = TorStream circuit
                    do! descriptorsStream.ConnectToDirectory() |> Async.Ignore

                    let descriptorsHttpClient =
                        TorHttpClient(
                            descriptorsStream,
                            Constants.DefaultHttpHost
                        )

                    let! descriptorsStr =
                        descriptorsHttpClient.GetAsString
                            (sprintf
                                "/tor/micro/d/%s"
                                (String.concat "-" digestsChunk))
                            false

                    let trimmedDescriptors = descriptorsStr.TrimEnd('\n')

                    return
                        MicroDescriptorEntry.ParseMany trimmedDescriptors
                        |> List.map(fun descriptor ->
                            descriptor.Digest.Value, descriptor
                        )
                }

            let chunkedJobs =
                networkStatus.Routers
                |> Seq.choose(fun router -> router.MicroDescriptorDigest)
                |> Seq.chunkBySize 96
                |> Seq.map downloadDescriptorsForChunk

            let! downloadResults = Async.Parallel(chunkedJobs, 16)

            let descriptorsMap = downloadResults |> List.concat |> Map.ofList

            return
                {
                    TorDirectory.NetworkStatus = networkStatus
                    ServerDescriptors = descriptorsMap
                }
        }


    member self.GetLiveNetworkStatus() =
        async {
            do! self.UpdateConsensusIfNotLive()
            return self.NetworkStatus
        }

    /// WARNING: this function is scary and might throw KeyNotFoundException.
    /// This function is currently used to calculate hidden service directory
    /// hashring which is done in a non-async fashion, hence why we don't try
    /// to find missing descriptors.
    member self.GetDescriptorByIdentity(b64Identity: string) =
        let routerEntryOpt =
            self.NetworkStatus.Routers
            |> List.tryFind(fun router -> router.Identity.Value = b64Identity)

        match routerEntryOpt with
        | None -> failwith "can't find router in the main consensus"
        | Some routerEntry ->
            self.ServerDescriptors.[routerEntry.MicroDescriptorDigest.Value]

    static member BootstrapAsync(nodeEndPoint: IPEndPoint) =
        TorDirectory.Bootstrap nodeEndPoint |> Async.StartAsTask

    member self.GetResponsibleHiddenServiceDirectories
        (blindedPublicKey: array<byte>)
        (sharedRandomValue: string)
        (periodNumber: uint64)
        (periodLength: uint64)
        (directoriesToAdd: int)
        =
        async {

            let! networkStatus = self.GetLiveNetworkStatus()

            let ByteArrayCompare (x: array<byte>) (y: array<byte>) =
                let xlen = x.Length
                let ylen = y.Length

                let len =
                    if xlen < ylen then
                        xlen
                    else
                        ylen

                let mutable index = 0
                let mutable result = 0

                while index < len do
                    let diff = (int(x.[index])) - int(y.[index])

                    if diff <> 0 then
                        index <- len + 1 // breaks out of the loop, and signals that result is valid
                        result <- diff
                    else
                        index <- index + 1

                if index > len then
                    result
                else
                    (xlen - ylen)

            let directories =
                networkStatus.GetHiddenServiceDirectories()
                |> List.choose(fun node ->
                    try
                        (node.GetIdentity(),
                         Array.concat
                             [
                                 "node-idx" |> Encoding.ASCII.GetBytes
                                 (node.GetIdentity()
                                  |> self.GetDescriptorByIdentity)
                                     .Ed25519Identity
                                     .Value
                                 |> Base64Util.FromString
                                 sharedRandomValue |> Convert.FromBase64String
                                 periodNumber
                                 |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                 periodLength
                                 |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                             ]
                         |> HiddenServicesCipher.SHA3256)
                        |> Some
                    with
                    | :? System.Collections.Generic.KeyNotFoundException ->
                        //We don't have the descriptor for this server
                        None
                )
                |> List.sortWith(fun (_, idx1) (_, idx2) ->
                    ByteArrayCompare idx1 idx2
                )

            let rec getRoutersToFetch (replicaNum: int) (state: list<string>) =
                if replicaNum > Constants.HiddenServices.Hashring.ReplicasNum then
                    state
                else
                    let hsIndex =
                        Array.concat
                            [
                                "store-at-idx" |> Encoding.ASCII.GetBytes
                                blindedPublicKey
                                replicaNum
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                periodLength
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                periodNumber
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            ]
                        |> HiddenServicesCipher.SHA3256

                    //FIXME: binary serach idx here
                    let start =
                        directories
                        |> Seq.tryFindIndex(fun (_, index) ->
                            ByteArrayCompare index hsIndex >= 0
                        )
                        |> Option.defaultValue 0

                    let rec pickNodes startIndex nToAdd state =
                        if nToAdd = 0 then
                            state
                        else
                            let node = fst directories.[startIndex]

                            let nextIndex =
                                let idx = startIndex + 1

                                if idx = directories.Length then
                                    0
                                else
                                    idx

                            if not(state |> Seq.contains node) then
                                if nextIndex = start then
                                    node :: state
                                else
                                    pickNodes
                                        nextIndex
                                        (nToAdd - 1)
                                        (node :: state)
                            else if nextIndex = start then
                                state
                            else
                                pickNodes nextIndex nToAdd state

                    getRoutersToFetch
                        (replicaNum + 1)
                        (pickNodes start directoriesToAdd state)

            return getRoutersToFetch 1 List.empty
        }
