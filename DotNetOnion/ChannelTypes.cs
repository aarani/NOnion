using DotNetOnion.Cells;

namespace DotNetOnion
{
    public class TorMessage
    {
        public ushort CircuitId { get; set; }
        public Cell Cell { get; set; }

    }
    public class TorFrame
    {
        public ushort CircuitId { get; set; }
        public byte Command { get; set; }
        public byte[] Payload { get; set; }
    }
}