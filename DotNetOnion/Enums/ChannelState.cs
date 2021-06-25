using System;
using System.Collections.Generic;
using System.Text;

namespace DotNetOnion
{
    public enum ChannelState
    {
        Disconnected,
        Connected,
        HandshakeInProgress,
        Active
    }
}
