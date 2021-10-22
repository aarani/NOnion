namespace NOnion.Network

open System.Threading.Tasks

open Org.BouncyCastle.Crypto.Parameters

open NOnion
open NOnion.Crypto
open NOnion.TorHandshakes
open NOnion.Cells.Relay

//TODO: Implement states like destroyed, truncated, etc...

type TorCircuitNode =
    {
        CryptoState: TorCryptoState
        Window: TorWindow
    }

type CircuitState =
    | Initialized
    | Creating of
        circuitId: uint16 *
        handshakeState: IHandshake *
        completionTask: TaskCompletionSource<uint16>
    | Extending of
        circuitId: uint16 *
        handshakeState: IHandshake *
        currentCircuitNodes: List<TorCircuitNode> *
        completionTask: TaskCompletionSource<uint16>
    | RegisteringAsIntorductionPoint of
        circuitId: uint16 *
        circuitNodes: List<TorCircuitNode> *
        privateKey: Ed25519PrivateKeyParameters *
        publicKey: Ed25519PublicKeyParameters *
        completionTask: TaskCompletionSource<unit> *
        callback: (RelayIntroduce -> Async<unit>)
    | RegisteringAsRendezvousPoint of
        circuitId: uint16 *
        circuitNodes: List<TorCircuitNode> *
        completionTask: TaskCompletionSource<unit>
    | WaitingForIntroduceAcknowledge of
        circuitId: uint16 *
        circuitNodes: List<TorCircuitNode> *
        completionTask: TaskCompletionSource<RelayIntroduceAck>
    | WaitingForRendezvousRequest of
        circuitId: uint16 *
        circuitNodes: List<TorCircuitNode> *
        clientRandomPrivateKey: X25519PrivateKeyParameters *
        clientRandomPublicKey: X25519PublicKeyParameters *
        introAuthPublicKey: Ed25519PublicKeyParameters *
        introEncPublicKey: X25519PublicKeyParameters *
        completionTask: TaskCompletionSource<unit>
    | Ready of circuitId: uint16 * circuitNodes: List<TorCircuitNode>
    | ReadyAsIntroductionPoint of
        circuitId: uint16 *
        circuitNodes: List<TorCircuitNode> *
        privateKey: Ed25519PrivateKeyParameters *
        publicKey: Ed25519PublicKeyParameters *
        callback: (RelayIntroduce -> Async<unit>)
    | ReadyAsRendezvousPoint of
        circuitId: uint16 *
        circuitNodes: List<TorCircuitNode>
    | Destroyed of circuitId: uint16 * reason: DestroyReason
    | Truncated of circuitId: uint16 * reason: DestroyReason


    member self.Name =
        match self with
        | Initialized -> "Initialized"
        | Creating _ -> "Creating"
        | Extending _ -> "Extending"
        | RegisteringAsIntorductionPoint _ -> "RegisteringAsIntorductionPoint"
        | RegisteringAsRendezvousPoint _ -> "RegisteringAsRendezvousPoint"
        | WaitingForIntroduceAcknowledge _ -> "WaitingForIntroduceAcknowledge"
        | WaitingForRendezvousRequest _ -> "WaitingForRendezvousRequest"
        | Ready _ -> "Ready"
        | ReadyAsIntroductionPoint _ -> "ReadyAsIntroductionPoint"
        | ReadyAsRendezvousPoint _ -> "ReadyAsRendezvousPoint"
        | Destroyed _ -> "Destroyed"
        | Truncated _ -> "Truncated"
