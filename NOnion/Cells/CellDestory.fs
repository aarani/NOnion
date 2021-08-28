namespace NOnion.Cells

open System.IO

(*
    The payload of a DESTROY cell contains a single octet, describing the
    reason that the circuit was closed.

    The error codes are:
         0 -- NONE            (No reason given.)
         1 -- PROTOCOL        (Tor protocol violation.)
         2 -- INTERNAL        (Internal error.)
         3 -- REQUESTED       (A client sent a TRUNCATE command.)
         4 -- HIBERNATING     (Not currently operating; trying to save bandwidth.)
         5 -- RESOURCELIMIT   (Out of memory, sockets, or circuit IDs.)
         6 -- CONNECTFAILED   (Unable to reach relay.)
         7 -- OR_IDENTITY     (Connected to relay, but its OR identity was not
                               as expected.)
         8 -- CHANNEL_CLOSED  (The OR connection that was carrying this circuit
                               died.)
         9 -- FINISHED        (The circuit has expired for being dirty or old.)
        10 -- TIMEOUT         (Circuit construction took too long)
        11 -- DESTROYED       (The circuit was destroyed w/o client TRUNCATE)
        12 -- NOSUCHSERVICE   (Request for unknown hidden service)
*)

type CellDestroy =
    {
        Reason: byte
    }

    static member Deserialize (reader: BinaryReader) =
        {
            Reason = reader.ReadByte ()
        }
        :> ICell

    interface ICell with

        member __.Command = 4uy

        member self.Serialize writer =
            writer.Write self.Reason
