namespace NOnion.Network

open System
open System.Security.Cryptography
open System.Threading.Tasks

open NOnion
open NOnion.Cells
open NOnion.Crypto
open NOnion.Crypto.Kdf
open NOnion.Utility

type TorCircuit (guard: TorGuard) =
    let mutable circuitState: CircuitState = CircuitState.Initialized
    let controlLock: SemaphoreLocker = SemaphoreLocker ()

    let window = TorWindow Constants.DefaultCircuitLevelWindowParams

    let mutable streamsCount: int = 1
    let mutable streamsMap: Map<uint16, ITorStream> = Map.empty
    // Prevents two stream setup happening at once (to prevent race condition on writing to StreamIds list)
    let streamSetupLock: obj = obj ()

    member __.SendRelayCell (streamId: uint16) (relayData: RelayData) =
        async {
            let safeSend () =
                async {
                    match circuitState with
                    | Created (circuitId, cryptoState) ->
                        let plainRelayCell =
                            CellPlainRelay.Create
                                streamId
                                relayData
                                (Array.zeroCreate Constants.RelayDigestLength)

                        let relayPlainBytes = plainRelayCell.ToBytes true

                        cryptoState.ForwardDigest.Update
                            relayPlainBytes
                            0
                            relayPlainBytes.Length

                        let digest =
                            cryptoState.ForwardDigest.GetDigestBytes ()
                            |> Array.take Constants.RelayDigestLength

                        let plainRelayCell =
                            { plainRelayCell with
                                Digest = digest
                            }

                        window.PackageDecrease ()

                        do!
                            {
                                CellEncryptedRelay.EncryptedData =
                                    plainRelayCell.ToBytes false
                                    |> cryptoState.ForwardCipher.Encrypt
                            }
                            |> guard.Send circuitId
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
            | Created (circuitId, cryptoState) ->
                let decryptedRelayCellBytes =
                    cryptoState.BackwardCipher.Encrypt
                        encryptedRelayCell.EncryptedData

                let recognized =
                    System.BitConverter.ToUInt16 (
                        decryptedRelayCellBytes,
                        Constants.RelayRecognizedOffset
                    )

                if recognized <> Constants.RecognizedDefaultValue then
                    failwith "Incoming cell is unrecognizable"

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
                    cryptoState.BackwardDigest.PeekDigest
                        decryptedRelayCellBytes
                        0
                        decryptedRelayCellBytes.Length
                    |> Array.take Constants.RelayDigestLength

                if digest <> computedDigest then
                    failwith "Digest verification for incoming cell failed"

                cryptoState.BackwardDigest.Update
                    decryptedRelayCellBytes
                    0
                    decryptedRelayCellBytes.Length

                let decryptedRelayCell =
                    CellPlainRelay.FromBytes decryptedRelayCellBytes


                (decryptedRelayCell.StreamId, decryptedRelayCell.Data)
            | _ ->

                failwith "Unexpected state when receiving relay cell"

        controlLock.RunSyncWithSemaphore safeDecryptCell

    member self.CreateFast () =
        async {
            let createFast () =
                async {
                    let circuitId = guard.RegisterCircuit self

                    let randomClientMaterial =
                        Array.zeroCreate<byte> Constants.HashLength

                    RandomNumberGenerator
                        .Create()
                        .GetBytes randomClientMaterial

                    let connectionCompletionSource = TaskCompletionSource ()

                    circuitState <-
                        CreatingFast (
                            circuitId,
                            randomClientMaterial,
                            connectionCompletionSource
                        )

                    do!
                        guard.Send
                            circuitId
                            {
                                CellCreateFast.X = randomClientMaterial
                            }

                    return connectionCompletionSource.Task
                }

            let! completionTask = controlLock.RunAsyncWithSemaphore createFast

            //FIXME: Connect Timeout?
            return! completionTask |> Async.AwaitTask
        }

    member self.CreateFastAsync () =
        self.CreateFast () |> Async.StartAsTask

    member internal __.RegisterStream (stream: ITorStream) : uint16 =
        let safeRegister () =
            let newId = uint16 streamsCount
            streamsCount <- streamsCount + 1
            streamsMap <- streamsMap.Add (newId, stream)
            newId

        lock streamSetupLock safeRegister

    interface ITorCircuit with
        member self.HandleIncomingCell (cell: ICell) =
            async {
                //TODO: Handle circuit-level cells like destroy/truncate/extended etc..
                match cell with
                | :? CellCreatedFast as createdMsg ->
                    let handleCreatedFast () =
                        match circuitState with
                        | CreatingFast (circuitId, randomClientMaterial, tcs) ->
                            let kdfResult =
                                Array.concat [ randomClientMaterial
                                               createdMsg.Y ]
                                |> Kdf.computeLegacyKdf

                            if kdfResult.KeyHandshake
                               <> createdMsg.DerivativeKeyData then
                                failwith "Key handshake failed!"

                            circuitState <-
                                Created (
                                    circuitId,
                                    TorCryptoState.FromKdfResult kdfResult
                                )

                            tcs.SetResult circuitId
                        | _ ->
                            failwith
                                "Unexpected circuit state when receiving CreatedFast cell"

                    controlLock.RunSyncWithSemaphore handleCreatedFast

                | :? CellEncryptedRelay as enRelay ->
                    let streamId, relayData = self.DecryptCell enRelay

                    match relayData with
                    | RelayData.RelayData _ ->
                        window.DeliverDecrease ()

                        if window.NeedSendme () then
                            do!
                                self.SendRelayCell
                                    Constants.DefaultCircuitId
                                    RelayData.RelaySendMe
                    | RelaySendMe _ when streamId = Constants.DefaultStreamId ->
                        window.PackageIncrease ()
                    | _ -> ()

                    if streamId <> Constants.DefaultStreamId then
                        match streamsMap.TryFind streamId with
                        | Some stream -> do! stream.HandleIncomingData relayData
                        | None -> failwith "Unknown stream"
                | _ -> ()
            }
