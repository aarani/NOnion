namespace NOnion.Utility

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Digests

module DigestUtils =
    let CreateDigestInstance
        (isSha3256: bool)
        (previousDigestOpt: Option<IDigest>)
        : IDigest =
        match isSha3256, previousDigestOpt with
        | false, None -> Sha1Digest() :> IDigest
        | false, Some previousDigest ->
            Sha1Digest(previousDigest :?> Sha1Digest) :> IDigest
        | true, None -> Sha3Digest() :> IDigest
        | true, Some previousDigest ->
            Sha3Digest(previousDigest :?> Sha3Digest) :> IDigest
