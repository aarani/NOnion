namespace NOnion.TorHandshakes

open NOnion.Cells
open NOnion.Crypto.Kdf

type IHandshake =
    abstract GenerateClientMaterial : unit -> array<byte>
    abstract GenerateKdfResult : ICreatedCell -> KdfResult
