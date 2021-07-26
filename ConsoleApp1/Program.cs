using System;
using System.Net;
using System.Reactive.Linq;
using System.Threading.Tasks;
using NOnion;
using NOnion.Cells;

namespace ConsoleApp1
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var guard = await TorGuard.NewClient(IPEndPoint.Parse("195.176.3.19:8443"));
            var circuit = await TorCircuit.CreateFast(guard);
            Console.WriteLine("Created circuit, Id: {0}", circuit.Id);

            var stream = await TorStream.CreateDirectoryStream(circuit);

            Console.ReadKey();
        }
    }
}
