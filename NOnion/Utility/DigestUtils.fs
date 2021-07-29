namespace NOnion.Utility

open Org.BouncyCastle.Crypto.Digests

module DigestUtils =
    let CreateDigestInstance
        (isSha256: bool)
        (previousDigestOpt: Option<GeneralDigest>)
        : GeneralDigest =
        match isSha256, previousDigestOpt with
        | false, None -> Sha1Digest () :> GeneralDigest
        | false, Some previousDigest ->
            Sha1Digest (previousDigest :?> Sha1Digest) :> GeneralDigest
        | true, None -> Sha256Digest () :> GeneralDigest
        | true, Some previousDigest ->
            Sha256Digest (previousDigest :?> Sha256Digest) :> GeneralDigest
