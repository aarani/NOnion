namespace NOnion.Utility

open System

module Base64Util =
    let private modulus = 4
    let private paddingCharacter = "="

    let FixMissingPadding(input: string) =
        (*
         * Length of base64 strings should be divisble by 4 or they'll be padded with =
         * According to tor directory spec, "The trailing '=' sign MAY be omitted from the base64 encoding"
         * But .NET base64 implemetation rejects non-padded base64 strings, so we need to add the padding
         * back before trying to decode it.
         *)
        let missingPadding = (input.Length % modulus)

        if missingPadding > 0 then
            input
            + (String.replicate (modulus - missingPadding) paddingCharacter)
        else
            input

    let FromString(input: string) =
        FixMissingPadding input |> System.Convert.FromBase64String

    let ToStringNoPad(input: array<byte>) =
        (Convert.ToBase64String input).TrimEnd([| '=' |])
