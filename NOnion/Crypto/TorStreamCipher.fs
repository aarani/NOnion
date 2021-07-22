namespace NOnion.Crypto

open System.Security.Cryptography
open System

type TorStreamCipher (keyBytes: array<byte>, ivOpt: Option<array<byte>>) =

    [<Literal>]
    let BlockSize = 16

    let mutable counter: array<byte> = Array.zeroCreate BlockSize
    let mutable counterOut: array<byte> = Array.zeroCreate BlockSize
    let mutable keyStreamPointer: int = -1

    let encryptLock: obj = obj ()

    let cipher: RijndaelManaged =
        new RijndaelManaged (
            Key = keyBytes,
            Mode = CipherMode.ECB,
            Padding = PaddingMode.None
        )

    do
        if ivOpt.IsSome && ivOpt.Value.Length = BlockSize then
            counter <- ivOpt.Value

    member private self.EncryptCounter () =
        let encryptedCounter =
            cipher
                .CreateEncryptor()
                .TransformFinalBlock (counter, 0, BlockSize)

        Array.blit encryptedCounter 0 counterOut 0 BlockSize

    member private self.IncreamentCounter () =
        let rec innerIncreament i (carry: int) =
            if i < 0 then
                ()
            else
                let x = (int (counter.[i]) &&& 0xff) + carry

                let carry: int =
                    if (x > 0xff) then
                        1
                    else
                        0

                counter.[i] <- byte (x)
                innerIncreament (i - 1) carry

        innerIncreament (counter.Length - 1) 1

    member private self.UpdateCounter () =
        self.EncryptCounter ()
        self.IncreamentCounter ()
        keyStreamPointer <- 0

    member private self.NextKeystreamByte () =
        if keyStreamPointer = -1 || keyStreamPointer >= BlockSize then
            self.UpdateCounter ()

        keyStreamPointer <- keyStreamPointer + 1
        counterOut.[keyStreamPointer - 1]

    member self.Encrypt (data: array<byte>) : array<byte> =
        let safeEncrypt () =
            let rec innerEncrypt (x: int) (state: array<byte>) =
                if x >= data.Length then
                    state
                else
                    let nextByte = (data.[x] ^^^ self.NextKeystreamByte ())
                    innerEncrypt (x + 1) (Array.append state [| nextByte |])

            innerEncrypt 0 Array.empty

        lock encryptLock safeEncrypt

    interface IDisposable with
        member self.Dispose () =
            cipher.Dispose ()
