using System;
using System.Collections.Generic;
using System.Text;

namespace DotNetOnion
{
    public static class Constants
    {
        public static readonly ushort[] SupportedVersion = { 3 };
        public static readonly int FixedPayloadLength = 209;

        public static readonly int HashLength = 20;
    }
}
