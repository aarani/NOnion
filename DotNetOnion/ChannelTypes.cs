using DotNetOnion.Cells;

namespace DotNetOnion
{
    internal class TorMessage
    {
        public ushort CircuitId { get; init; }
        public Cell Cell { get; init; }

    }
    internal class TorFrame
    {
        public ushort CircuitId { get; init; }
        public byte Command { get; init; }
        public byte[] Payload { get; init; }
    }
}