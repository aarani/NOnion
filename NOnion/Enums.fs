namespace NOnion

open System
open System.Net.Security

open NOnion.Crypto

type GuardState =
    | Initialized
    | Connecting of secureStream: SslStream
    | Connected of secureStream: SslStream * version: uint16
    | Disconnected

and CircuitState =
    | Initialized
    | CreatingFast of circuitId: uint16 * randomClientMaterial: array<byte>
    | Created of circuitId: uint16 * cryptoState: TorCryptoState
    //TODO:
    | Destroyed of Reason: byte
    | Truncated
