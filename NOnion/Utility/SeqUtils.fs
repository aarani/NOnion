namespace NOnion

module SeqUtils =
    let chunk n xs =
        seq {
            let i = ref 0
            let arr = ref <| Array.create n (Unchecked.defaultof<'a>)

            for x in xs do
                if !i = n then
                    yield !arr
                    arr := Array.create n (Unchecked.defaultof<'a>)
                    i := 0

                (!arr).[!i] <- x
                i := !i + 1

            if !i <> 0 then
                yield (!arr).[0..!i - 1]
        }
