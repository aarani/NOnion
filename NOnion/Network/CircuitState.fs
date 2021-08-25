namespace NOnion.Network

open System.Threading.Tasks

open NOnion.Crypto
open NOnion.TorHandshakes

//TODO: Implement states like destroyed, truncated, etc...
type CircuitState =
    | Initialized
    | Creating of
        circuitId: uint16 *
        handshakeState: IHandshake *
        completionTask: TaskCompletionSource<uint16>
    | Created of circuitId: uint16 * cryptoState: TorCryptoState
