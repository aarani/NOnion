namespace NOnion


open System.Security.Cryptography

open NOnion.Crypto.Kdf
open NOnion.Utility
open NOnion.Cells
open FSharpx.Control.Observable
open FSharp.Control.Reactive
open NOnion.Crypto
open System

type TorCircuit private (id: uint16, guard: TorGuard, kdfResult: KdfResult) as self =

    let circuitId = id
    let cryptoState = TorCryptoState.FromKdfResult kdfResult
    let guard = guard

    //TODO: make cryptostate immutable and use mapFold
    //TODO: make sure late subscription doesn't make any problem here
    let circuitMessages =
        guard.CircuitMessages circuitId
        |> Observable.ofType
        |> Observable.map self.DecryptCell
        |> Observable.publish

    let subscription = circuitMessages.Connect ()

    member self.StreamMessages (streamId: uint16) =
        circuitMessages
        |> Observable.filter (fun (sid, _) -> sid = streamId)
        |> Observable.map (fun (_, cell) -> cell)

    member self.Id = circuitId

    member self.Send (streamId: uint16) (relayData: RelayData) =
        async {
            let plainRelayCell =
                CellPlainRelay.Create streamId relayData (Array.zeroCreate 4)

            let relayPlainBytes = plainRelayCell.ToBytes true

            cryptoState.ForwardDigest.Update
                relayPlainBytes
                0
                relayPlainBytes.Length

            let digest =
                cryptoState.ForwardDigest.GetDigestBytes () |> Array.take 4

            let plainRelayCell =
                { plainRelayCell with
                    Digest = digest
                }

            do!
                {
                    CellEncryptedRelay.EncryptedData =
                        plainRelayCell.ToBytes false
                        |> cryptoState.ForwardCipher.Encrypt
                }
                |> guard.Send id
        }
        |> Async.StartAsTask

    member private self.DecryptCell (encryptedRelayCell: CellEncryptedRelay) =
        let decryptedRelayCellBytes =
            cryptoState.BackwardCipher.Encrypt encryptedRelayCell.EncryptedData

        let recognized =
            System.BitConverter.ToUInt16 (decryptedRelayCellBytes, 1)

        if recognized <> 0us then
            failwith "wat?"

        let digest = decryptedRelayCellBytes |> Array.skip 5 |> Array.take 4
        Array.fill decryptedRelayCellBytes 5 4 0uy

        let computedDigest =
            cryptoState.BackwardDigest.PeekDigest
                decryptedRelayCellBytes
                0
                decryptedRelayCellBytes.Length
            |> Array.take 4

        if digest <> computedDigest then
            failwith "wat"

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

                let randomBytes = Array.zeroCreate<byte> 2

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

            do!
                guard.Send
                    circuitId
                    {
                        CellCreateFast.X = randomClientMaterial
                    }

            let! createdMsg =
                guard.CircuitMessages circuitId
                |> Observable.ofType
                |> Async.AwaitObservable

            let kdfResult =
                Array.concat [ randomClientMaterial
                               createdMsg.Y ]
                |> Kdf.computeLegacyKdf

            if kdfResult.KeyHandshake <> createdMsg.DerivativeKeyData then
                failwith "Bad key handshake"

            return new TorCircuit (circuitId, guard, kdfResult)
        }
        |> Async.StartAsTask


    interface IDisposable with
        member self.Dispose () =
            subscription.Dispose ()
