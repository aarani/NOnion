namespace NOnion

open System.Threading.Tasks

open NOnion.Crypto

//TODO: Implement states like destroyed, truncated, etc...
type CircuitState =
    | Initialized
    | CreatingFast of
        circuitId: uint16 *
        randomClientMaterial: array<byte> *
        completionTask: TaskCompletionSource<uint16>
    | Created of circuitId: uint16 * cryptoState: TorCryptoState
