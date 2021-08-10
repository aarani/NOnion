namespace NOnion

open System
open System.Reactive.Subjects
open System.Security.Cryptography
open System.Threading

open FSharpx.Control.Observable

open NOnion.Cells
open NOnion.Crypto
open NOnion.Crypto.Kdf
open NOnion.Utility

type TorCircuit
    private
    (
        circuitId: uint16,
        guard: TorGuard,
        kdfResult: KdfResult
    ) as self =

    let cryptoState = TorCryptoState.FromKdfResult kdfResult
    // Prevents multiple write from breaking the cryptoState because of RC
    let sendLock: obj = obj ()

    let streamsMessages = new Subject<uint16 * RelayData> ()

    let window = TorWindow Constants.DefaultCircuitLevelWindowParams

    let mutable streamsCount: int = 1
    // Prevents two stream setup happening at once (to prevent race condition on writing to StreamIds list)
    let streamSetupLock: obj = obj ()

    let subscription =
        guard.MessageReceived
        |> ObservableUtils.FilterByKey circuitId
        |> Observable.subscribe self.HandleIncomingMessage

    member __.StreamsMessages =
        streamsMessages :> IObservable<uint16 * RelayData>

    member __.Id = circuitId

    member __.Send (streamId: uint16) (relayData: RelayData) =
        async {
            Monitor.Enter sendLock

            try
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
            finally
                Monitor.Exit sendLock
        }

    member self.HandleIncomingMessage cell =
        match cell with
        | :? CellEncryptedRelay as enRelay ->
            let streamId, relayData = self.DecryptCell enRelay

            match relayData with
            | RelayData.RelayData _ ->
                window.DeliverDecrease ()

                if window.NeedSendme () then
                    //TODO: Is RunSynchronously a good idea?
                    self.Send Constants.DefaultCircuitId RelayData.RelaySendMe
                    |> Async.RunSynchronously
            | RelaySendMe _ when streamId = Constants.DefaultStreamId ->
                window.PackageIncrease ()
            | _ -> ()

            if streamId <> Constants.DefaultStreamId then
                streamsMessages.OnNext (streamId, relayData)
        | _ -> ()
    //TODO: Handle circuit-level cells like destroy/truncate/extended etc..

    member private __.DecryptCell (encryptedRelayCell: CellEncryptedRelay) =
        let decryptedRelayCellBytes =
            cryptoState.BackwardCipher.Encrypt encryptedRelayCell.EncryptedData

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

    static member CreateFast (guard: TorGuard) =
        async {
            let rec createCircuitId (retry: int) =
                if retry >= Constants.MaxCircuitIdGenerationRetry then
                    failwith "can't create a circuit"

                let randomBytes =
                    Array.zeroCreate<byte> Constants.CircuitIdLength

                RandomNumberGenerator
                    .Create()
                    .GetBytes randomBytes

                let cid =
                    IntegerSerialization.FromBigEndianByteArrayToUInt16
                        randomBytes

                if guard.RegisterCircuitId cid then
                    cid
                else
                    createCircuitId (retry + 1)

            let circuitId = createCircuitId 0

            let randomClientMaterial =
                Array.zeroCreate<byte> Constants.HashLength

            RandomNumberGenerator
                .Create()
                .GetBytes randomClientMaterial

            // We start the handler before we send the Create request to make sure we don't miss the created event

            let createdMsg =
                guard.MessageReceived
                |> ObservableUtils.FilterByKey circuitId
                |> Observable.choose (fun cell ->
                    match cell with
                    | :? CellCreatedFast as createdFast -> Some createdFast
                    | _ -> None
                )
                |> Async.AwaitObservable

            do!
                guard.Send
                    circuitId
                    {
                        CellCreateFast.X = randomClientMaterial
                    }

            let! createdMsg = createdMsg

            let kdfResult =
                Array.concat [ randomClientMaterial
                               createdMsg.Y ]
                |> Kdf.computeLegacyKdf

            if kdfResult.KeyHandshake <> createdMsg.DerivativeKeyData then
                failwith "Key handshake failed!"

            return new TorCircuit (circuitId, guard, kdfResult)
        }

    static member CreateFastAsync guard =
        TorCircuit.CreateFast guard |> Async.StartAsTask

    member internal __.RegisterStreamId () : uint16 =
        let safeRegister () =
            let newId = uint16 streamsCount
            streamsCount <- streamsCount + 1
            newId

        lock streamSetupLock safeRegister

    interface IDisposable with
        member __.Dispose () =
            subscription.Dispose ()
            streamsMessages.OnCompleted ()
            streamsMessages.Dispose ()
