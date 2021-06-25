using System;
using System.Collections.Generic;
using System.Text;

namespace DotNetOnion
{
    internal static class Constants
    {
        public static readonly ushort[] SupportedVersion = { 3 };
        public static readonly int FixedPayloadLength = 509;

        public static readonly int HashLength = 20;
        public static readonly int KeyLength = 16;
    }
}
