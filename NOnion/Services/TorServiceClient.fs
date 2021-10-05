namespace NOnion.Network

open System.Security.Cryptography

open NOnion.Directory

type TorServiceClient (directory: TorDirectory) =

    member self.CreateRendezvousPoint () =
        async {

            return ()
        }
