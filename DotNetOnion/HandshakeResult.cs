using DotNetOnion.Cells;
using NOnion.Cells;

namespace DotNetOnion
{
    public class HandshakeResult
    {
        public CellVersions Versions { get; set; }
        public CellCerts Certs { get; set; }
        public CellAuthChallenge AuthChallenge { get; set; }
        public CellNetInfo NetInfo { get; set; }

        public Status GetStatus()
        {
            if (Versions == null)
                return Status.WaitingForVersions;
            else if (Certs == null)
                return Status.WaitingForCerts;
            else if (AuthChallenge == null)
                return Status.WaitingForAuthChallenge;
            else if (NetInfo == null)
                return Status.WaitingForNetInfo;
            else
                return Status.Completed;
        }

        public enum Status
        {
            WaitingForVersions = 0,
            WaitingForCerts = 1,
            WaitingForAuthChallenge = 2,
            WaitingForNetInfo = 3,
            Completed = 4
        }
    }
}