using DotNetOnion.Cells;
using NOnion.Cells;

namespace DotNetOnion
{
    public class TorMessage
    {
        public ushort CircuitId { get; set; }
        public ICell Cell { get; set; }

    }
    public class TorFrame
    {
        public ushort CircuitId { get; set; }
        public byte Command { get; set; }
        public byte[] Payload { get; set; }
    }
}