using System;
using System.Collections.Generic;
using System.Text;

namespace DotNetOnion.Helpers
{
    internal static class DateTimeHelpers
    {
        public static uint ToUnixTimestamp(this DateTime dt)
        {
            TimeSpan t = dt - new DateTime(1970, 1, 1);
            return (uint)t.TotalSeconds;
        }
    }
}
