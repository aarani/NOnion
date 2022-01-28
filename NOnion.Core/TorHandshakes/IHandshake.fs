namespace NOnion.Core.TorHandshakes

open NOnion.Core.Cells
open NOnion.Core.Crypto.Kdf

type IHandshake =
    abstract GenerateClientMaterial: unit -> array<byte>
    abstract GenerateKdfResult: ICreatedCell -> KdfResult
