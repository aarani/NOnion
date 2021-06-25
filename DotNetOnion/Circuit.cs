using System.Threading.Tasks;

namespace DotNetOnion
{
    public class Circuit
    {
        private readonly ushort id;
        private readonly bool fastFirstHop;

        //TODO: more hops

        public Circuit(ushort id, bool fastFirstHop)
        {
            this.id = id;
            this.fastFirstHop = fastFirstHop;
        }

    }
}