namespace NOnion.Crypto

open NOnion.Utility

open Org.BouncyCastle.Crypto.Digests

(*
 * This class wraps bouncycastle's digest class for use in relay cell digest calculation.
 * We have to use bouncycastle's SHA instead of .NET's because .NET version have no option
 * to keep the state (for a running digest) but you can clone the BCL version before resetting the state.
 *)
type TorMessageDigest (isSha256: bool) =

    [<Literal>]
    let TOR_DIGEST256_SIZE = 32

    [<Literal>]
    let TOR_DIGEST_SIZE = 20

    let digestInstance = DigestUtils.CreateDigestInstance isSha256 None

    let hashSize =
        if isSha256 then
            TOR_DIGEST256_SIZE
        else
            TOR_DIGEST_SIZE

    new () = TorMessageDigest false

    member self.GetDigestBytes () : array<byte> =
        let hash = Array.zeroCreate<byte> hashSize

        let clone =
            DigestUtils.CreateDigestInstance isSha256 (Some digestInstance)

        clone.DoFinal (hash, 0) |> ignore<int>
        hash

    member self.PeekDigest
        (
            data: array<byte>,
            offset: int,
            length: int
        ) : array<byte> =
        let hash = Array.zeroCreate<byte> hashSize

        let clone =
            DigestUtils.CreateDigestInstance isSha256 (Some digestInstance)

        clone.BlockUpdate (data, offset, length) |> ignore<unit>
        clone.DoFinal (hash, 0) |> ignore<int>
        hash

    member self.Update (data: array<byte>) (offset: int) (length: int) =
        digestInstance.BlockUpdate (data, offset, length)
