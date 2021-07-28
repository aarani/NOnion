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
    let cryptoState = TorCryptoState.FromKdfResult (kdfResult)

    let subscription: IDisposable =
        guard.Messages
        |> Observable.filter (fun (cid, _) -> cid = id)
        |> Observable.subscribe (fun (_, cell) -> self.HandleNewMessage (cell))

    member self.Id = circuitId

    member self.HandleNewMessage (cell: ICell) =
        ()

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
                async {
                    let! message =
                        guard.Messages
                        |> Observable.filter (fun (cid, cell) ->
                            cid = circuitId
                            && cell.Command = Command.CreatedFast
                        )
                        |> Observable.map (fun (_, cell) -> cell)
                        |> Async.AwaitObservable

                    return message :?> CellCreatedFast
                }

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
