namespace NOnion.Network

open System
open System.Security.Cryptography
open System.Threading.Tasks
open System.Net

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

open NOnion
open NOnion.Cells
open NOnion.Cells.Relay
open NOnion.Crypto
open NOnion.TorHandshakes
open NOnion.Utility

type CircuitNodeDetail =
    {
        Address: Option<IPEndPoint>
        NTorOnionKey: array<byte>
        IdentityKey: array<byte>
    }

type TorCircuit (guard: TorGuard) =
    let mutable circuitState: CircuitState = CircuitState.Initialized
    let controlLock: SemaphoreLocker = SemaphoreLocker ()

    let mutable streamsCount: int = 1
    let mutable streamsMap: Map<uint16, ITorStream> = Map.empty
    // Prevents two stream setup happening at once (to prevent race condition on writing to StreamIds list)
    let streamSetupLock: obj = obj ()

    let mutable defaultStream: Option<ITorStream> = None

    member __.LastNode =
        match circuitState with
        | Ready (_, nodesStates) -> nodesStates |> List.rev |> List.head
        | _ -> failwith ""

    member private self.UnsafeSendRelayCell
        (streamId: uint16)
        (relayData: RelayData)
        (customDestinationOpt: Option<TorCircuitNode>)
        (early: bool)
        =
        async {
            match circuitState with
            | Ready (circuitId, nodesStates)
            | Extending (circuitId, _, nodesStates, _)
            | RegisteringAsIntorductionPoint (circuitId, nodesStates, _, _, _) ->
                let onionList, destination =
                    match customDestinationOpt with
                    | None ->
                        let reversedNodesList = nodesStates |> List.rev
                        reversedNodesList, reversedNodesList |> List.head

                    | Some destination ->
                        nodesStates
                        |> List.takeWhile (fun node -> node <> destination)
                        |> List.append (List.singleton destination)
                        |> List.rev,
                        destination

                let plainRelayCell =
                    CellPlainRelay.Create
                        streamId
                        relayData
                        (Array.zeroCreate Constants.RelayDigestLength)

                let relayPlainBytes = plainRelayCell.ToBytes true

                destination.CryptoState.ForwardDigest.Update
                    relayPlainBytes
                    0
                    relayPlainBytes.Length

                let digest =
                    destination.CryptoState.ForwardDigest.GetDigestBytes ()
                    |> Array.take Constants.RelayDigestLength

                let plainRelayCell =
                    { plainRelayCell with
                        Digest = digest
                    }

                let rec encryptMessage
                    (nodes: List<TorCircuitNode>)
                    (message: array<byte>)
                    =
                    match List.tryHead nodes with
                    | Some node ->
                        encryptMessage
                            (List.tail nodes)
                            (node.CryptoState.ForwardCipher.Encrypt message)
                    | None -> message

                do!
                    {
                        CellEncryptedRelay.EncryptedData =
                            plainRelayCell.ToBytes false
                            |> encryptMessage onionList
                        Early = early
                    }
                    |> guard.Send circuitId
            | _ ->
                failwith (
                    sprintf
                        "Can't relay cell over circuit, %s state"
                        (circuitState.ToString ())
                )
        }

    member self.SendRelayCell
        (streamId: uint16)
        (relayData: RelayData)
        (customDestinationOpt: Option<TorCircuitNode>)
        =
        async {
            let safeSend () =
                async {
                    match circuitState with
                    | Ready _ ->
                        return!
                            self.UnsafeSendRelayCell
                                streamId
                                relayData
                                customDestinationOpt
                                false
                    | _ ->
                        failwith (
                            sprintf
                                "Can't relay cell over circuit, %s state"
                                (circuitState.ToString ())
                        )
                }

            return! controlLock.RunAsyncWithSemaphore safeSend
        }

    member private __.DecryptCell (encryptedRelayCell: CellEncryptedRelay) =
        let safeDecryptCell () =
            match circuitState with
            | Ready (circuitId, nodes)
            | RegisteringAsIntorductionPoint (circuitId, nodes, _, _, _)
            | Extending (circuitId, _, nodes, _) ->
                let rec decryptMessage
                    (message: array<byte>)
                    (nodes: List<TorCircuitNode>)
                    =
                    match List.tryHead nodes with
                    | Some node ->
                        let decryptedRelayCellBytes =
                            node.CryptoState.BackwardCipher.Encrypt message

                        let recognized =
                            System.BitConverter.ToUInt16 (
                                decryptedRelayCellBytes,
                                Constants.RelayRecognizedOffset
                            )

                        if recognized <> Constants.RecognizedDefaultValue then
                            decryptMessage decryptedRelayCellBytes nodes.Tail
                        else
                            let digest =
                                decryptedRelayCellBytes
                                |> Array.skip Constants.RelayDigestOffset
                                |> Array.take Constants.RelayDigestLength

                            Array.fill
                                decryptedRelayCellBytes
                                Constants.RelayDigestOffset
                                Constants.RelayDigestLength
                                0uy

                            let computedDigest =
                                node.CryptoState.BackwardDigest.PeekDigest
                                    decryptedRelayCellBytes
                                    0
                                    decryptedRelayCellBytes.Length
                                |> Array.take Constants.RelayDigestLength

                            if digest <> computedDigest then
                                decryptMessage
                                    decryptedRelayCellBytes
                                    nodes.Tail
                            else
                                node.CryptoState.BackwardDigest.Update
                                    decryptedRelayCellBytes
                                    0
                                    decryptedRelayCellBytes.Length

                                let decryptedRelayCell =
                                    CellPlainRelay.FromBytes
                                        decryptedRelayCellBytes

                                (decryptedRelayCell.StreamId,
                                 decryptedRelayCell.Data,
                                 node)
                    | None -> failwith "Decryption failed!"

                decryptMessage encryptedRelayCell.EncryptedData nodes
            | _ -> failwith "Unexpected state when receiving relay cell"

        controlLock.RunSyncWithSemaphore safeDecryptCell

    member self.Create (guardDetailOpt: Option<CircuitNodeDetail>) =
        async {
            let create () =
                async {
                    match circuitState with
                    | CircuitState.Initialized ->
                        let circuitId = guard.RegisterCircuit self
                        let connectionCompletionSource = TaskCompletionSource ()

                        let handshakeState, handshakeCell =
                            match guardDetailOpt with
                            | None ->
                                let state =
                                    FastHandshake.Create () :> IHandshake

                                state,
                                {
                                    CellCreateFast.X =
                                        state.GenerateClientMaterial ()
                                }
                                :> ICell
                            | Some guardDetail ->
                                let state =
                                    NTorHandshake.Create
                                        guardDetail.IdentityKey
                                        guardDetail.NTorOnionKey
                                    :> IHandshake

                                state,
                                {
                                    CellCreate2.HandshakeType =
                                        HandshakeType.NTor
                                    HandshakeData =
                                        state.GenerateClientMaterial ()
                                }
                                :> ICell

                        circuitState <-
                            Creating (
                                circuitId,
                                handshakeState,
                                connectionCompletionSource
                            )

                        do! guard.Send circuitId handshakeCell

                        return connectionCompletionSource.Task
                    | _ -> return invalidOp "Circuit is already created"
                }

            let! completionTask = controlLock.RunAsyncWithSemaphore create

            return!
                completionTask
                |> AsyncUtil.AwaitTaskWithTimeout
                    Constants.CircuitOperationTimeout
        }

    member self.Extend (nodeDetail: CircuitNodeDetail) =
        async {
            if nodeDetail.Address.IsNone then
                invalidArg
                    "nodeDetail.Address"
                    "Node address should be specified for extending"

            let extend () =
                async {
                    match circuitState with
                    | CircuitState.Ready (circuitId, nodes) ->
                        let connectionCompletionSource = TaskCompletionSource ()

                        let translateIPEndpoint (endpoint: IPEndPoint) =
                            Array.concat
                                [
                                    endpoint.Address.GetAddressBytes ()
                                    endpoint.Port
                                    |> uint16
                                    |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                                ]

                        let handshakeState, handshakeCell =
                            let state =
                                NTorHandshake.Create
                                    nodeDetail.IdentityKey
                                    nodeDetail.NTorOnionKey
                                :> IHandshake

                            state,
                            {
                                RelayExtend2.LinkSpecifiers =
                                    [
                                        {
                                            LinkSpecifier.Type =
                                                LinkSpecifierType.TLSOverTCPV4
                                            Data =
                                                translateIPEndpoint
                                                    nodeDetail.Address.Value
                                        }
                                        {
                                            LinkSpecifier.Type =
                                                LinkSpecifierType.LegacyIdentity
                                            Data = nodeDetail.IdentityKey
                                        }
                                    ]
                                HandshakeType = HandshakeType.NTor
                                HandshakeData = state.GenerateClientMaterial ()
                            }
                            |> RelayData.RelayExtend2

                        circuitState <-
                            Extending (
                                circuitId,
                                handshakeState,
                                nodes,
                                connectionCompletionSource
                            )

                        do!
                            self.UnsafeSendRelayCell
                                Constants.DefaultStreamId
                                handshakeCell
                                None
                                true

                        return connectionCompletionSource.Task
                    | _ ->
                        return
                            invalidOp
                                "Circuit is not in a state suitable for extending"
                }

            let! completionTask = controlLock.RunAsyncWithSemaphore extend

            return!
                completionTask
                |> AsyncUtil.AwaitTaskWithTimeout
                    Constants.CircuitOperationTimeout

        }

    member self.RegisterAsIntroductionPoint
        (authKeyPairOpt: Option<AsymmetricCipherKeyPair>)
        =
        let registerAsIntroduction () =
            async {
                match circuitState with
                | Ready (circuitId, nodes) ->
                    let lastNode = self.LastNode

                    let authPrivateKey, authPublicKey =
                        let authKeyPair =
                            match authKeyPairOpt with
                            | Some authKeyPair -> authKeyPair
                            | None ->
                                let kpGen = Ed25519KeyPairGenerator ()
                                let random = SecureRandom ()

                                kpGen.Init (
                                    Ed25519KeyGenerationParameters random
                                )

                                kpGen.GenerateKeyPair ()

                        authKeyPair.Private :?> Ed25519PrivateKeyParameters,
                        authKeyPair.Public :?> Ed25519PublicKeyParameters

                    let establishIntroCell =
                        RelayEstablishIntro.Create
                            authPrivateKey
                            authPublicKey
                            lastNode.CryptoState.KeyHandshake
                        |> RelayData.RelayEstablishIntro

                    let connectionCompletionSource = TaskCompletionSource ()

                    circuitState <-
                        CircuitState.RegisteringAsIntorductionPoint (
                            circuitId,
                            nodes,
                            authPrivateKey,
                            authPublicKey,
                            connectionCompletionSource
                        )

                    do!
                        self.UnsafeSendRelayCell
                            Constants.DefaultStreamId
                            establishIntroCell
                            (Some lastNode)
                            false

                    return connectionCompletionSource.Task
                | _ ->
                    return
                        failwith
                            "Unexpected state for registering as introduction point"
            }

        async {
            let! completionTask =
                controlLock.RunAsyncWithSemaphore registerAsIntroduction

            return!
                completionTask
                |> AsyncUtil.AwaitTaskWithTimeout
                    Constants.CircuitOperationTimeout
        }

    member self.ExtendAsync nodeDetail =
        self.Extend nodeDetail |> Async.StartAsTask

    member self.CreateAsync guardDetailOpt =
        self.Create guardDetailOpt |> Async.StartAsTask

    member self.RegisterAsIntroductionPointAsync
        (authKeyPairOpt: Option<AsymmetricCipherKeyPair>)
        =
        self.RegisterAsIntroductionPoint authKeyPairOpt |> Async.StartAsTask

    member internal __.RegisterStream
        (stream: ITorStream)
        (isDefaultStream: bool)
        : uint16 =
        let safeRegister () =
            if isDefaultStream then
                defaultStream <- Some stream
                0us
            else
                let newId = uint16 streamsCount
                streamsCount <- streamsCount + 1
                streamsMap <- streamsMap.Add (newId, stream)
                newId

        lock streamSetupLock safeRegister

    interface ITorCircuit with
        member self.HandleIncomingCell (cell: ICell) =
            async {
                //TODO: Handle circuit-level cells like destroy/truncate etc..
                match cell with
                | :? ICreatedCell as createdMsg ->
                    let handleCreated () =
                        match circuitState with
                        | Creating (circuitId, handshakeState, tcs) ->
                            let kdfResult =
                                handshakeState.GenerateKdfResult createdMsg

                            circuitState <-
                                Ready (
                                    circuitId,
                                    List.singleton
                                        {
                                            TorCircuitNode.CryptoState =
                                                TorCryptoState.FromKdfResult
                                                    kdfResult
                                            Window =
                                                TorWindow
                                                    Constants.DefaultCircuitLevelWindowParams
                                        }
                                )

                            tcs.SetResult circuitId
                        | _ ->
                            failwith
                                "Unexpected circuit state when receiving CreatedFast cell"

                    controlLock.RunSyncWithSemaphore handleCreated
                | :? CellEncryptedRelay as enRelay ->
                    let streamId, relayData, fromNode = self.DecryptCell enRelay

                    match relayData with
                    | RelayData.RelayData _ ->
                        fromNode.Window.DeliverDecrease ()

                        if fromNode.Window.NeedSendme () then
                            do!
                                self.SendRelayCell
                                    Constants.DefaultStreamId
                                    RelayData.RelaySendMe
                                    (Some fromNode)
                    | RelayData.RelayExtended2 extended2 ->
                        let handleExtended () =
                            match circuitState with
                            | Extending (circuitId, handshakeState, nodes, tcs) ->
                                let kdfResult =
                                    handshakeState.GenerateKdfResult extended2

                                circuitState <-
                                    Ready (
                                        circuitId,
                                        nodes
                                        @ List.singleton
                                            {
                                                TorCircuitNode.CryptoState =
                                                    TorCryptoState.FromKdfResult
                                                        kdfResult
                                                Window =
                                                    TorWindow
                                                        Constants.DefaultCircuitLevelWindowParams
                                            }
                                    )

                                tcs.SetResult circuitId
                            | _ ->
                                failwith
                                    "Unexpected circuit state when receiving Extended cell"

                        controlLock.RunSyncWithSemaphore handleExtended

                    | RelayData.RelayEstablishedIntro _ ->
                        let handleEstablished () =
                            match circuitState with
                            | RegisteringAsIntorductionPoint (circuitId,
                                                              nodes,
                                                              _privateKey,
                                                              _publicKey,
                                                              tcs) ->
                                circuitState <-
                                    ReadyAsIntroductionPoint (
                                        circuitId,
                                        nodes,
                                        _privateKey,
                                        _publicKey
                                    )

                                tcs.SetResult ()
                            | _ ->
                                failwith
                                    "Unexpected circuit state when receiving ESTABLISHED_INTRO cell"

                        controlLock.RunSyncWithSemaphore handleEstablished
                    | RelaySendMe _ when streamId = Constants.DefaultStreamId ->
                        fromNode.Window.PackageIncrease ()
                    | RelayTruncated reason ->
                        let handleTruncated () =
                            match circuitState with
                            | Creating (circuitId, _, tcs)
                            | Extending (circuitId, _, _, tcs) ->

                                circuitState <- Truncated (circuitId, reason)

                                tcs.SetException (
                                    CircuitTruncatedException reason
                                )
                            | Ready (circuitId, _) ->
                                //FIXME: how can we tell the user that circuit is destroyed? if we throw here the listening thread with throw and user never finds out why
                                circuitState <- Truncated (circuitId, reason)
                            | _ ->
                                //FIXME: can this even happen?
                                ()

                        controlLock.RunSyncWithSemaphore handleTruncated
                    | _ -> ()

                    if streamId <> Constants.DefaultStreamId then
                        match streamsMap.TryFind streamId with
                        | Some stream -> do! stream.HandleIncomingData relayData
                        | None -> failwith "Unknown stream"
                    elif defaultStream.IsSome then
                        do! defaultStream.Value.HandleIncomingData relayData

                | :? CellDestroy as destroyCell ->
                    let handleDestroyed () =
                        match circuitState with
                        | Creating (circuitId, _, tcs)
                        | Extending (circuitId, _, _, tcs) ->

                            circuitState <-
                                Destroyed (circuitId, destroyCell.Reason)

                            tcs.SetException (
                                CircuitDestroyedException destroyCell.Reason
                            )

                        | Ready (circuitId, _) ->
                            //FIXME: how can we tell the user that circuit is destroyed? if we throw here the listening thread with throw and user never finds out why
                            circuitState <-
                                Destroyed (circuitId, destroyCell.Reason)
                        | _ ->
                            //FIXME: can this even happen?
                            ()

                    controlLock.RunSyncWithSemaphore handleDestroyed
                | _ -> ()
            }
