﻿namespace NOnion.Crypto.Kdf

type KdfResult =
    {
        KeyHandshake: array<byte>
        ForwardDigest: array<byte>
        BackwardDigest: array<byte>
        ForwardKey: array<byte>
        BackwardKey: array<byte>
        IsHSV3: bool
    }
