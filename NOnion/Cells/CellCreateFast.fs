namespace NOnion.Cells

open System.IO

open NOnion

(*
    When initializing the first hop of a circuit, the OP has already
    established the OR's identity and negotiated a secret key using TLS.
    Because of this, it is not always necessary for the OP to perform the
    public key operations to create a circuit.  In this case, the
    OP MAY send a CREATE_FAST cell instead of a CREATE cell for the first
    hop only.  The OR responds with a CREATED_FAST cell, and the circuit is
    created.

    A CREATE_FAST cell contains:
        Key material (X)    [HASH_LEN bytes]

    The CREATE_FAST handshake is currently deprecated whenever it is not
    necessary; the migration is controlled by the "usecreatefast"
    networkstatus parameter as described in dir-spec.txt.
*)

type CellCreateFast =
    {
        X: array<byte>
    }

    static member Deserialize (reader: BinaryReader) =
        let x = reader.ReadBytes Constants.HashLength

        {
            X = x
        }
        :> ICell

    interface ICell with

        member __.Command = 5uy

        member self.Serialize writer =
            writer.Write self.X
