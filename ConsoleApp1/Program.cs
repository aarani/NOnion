using System;
using System.Text;
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
            var guard = await TorGuard.NewClientAsTask(IPEndPoint.Parse("195.176.3.19:8443"));
            var circuit = await TorCircuit.CreateFastAsTask(guard);
            Console.WriteLine("Created circuit, Id: {0}", circuit.Id);

            var stream = await TorStream.CreateDirectoryStreamAsTask(circuit);
            stream.DataReceived.Subscribe((newData) => Console.WriteLine(Encoding.UTF8.GetString(newData)));
            string request = $"GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: 195.176.3.19\r\n\r\n";
            var requestBytes = Encoding.UTF8.GetBytes(request);
            await stream.SendAsTask(requestBytes);

            Console.ReadKey();
        }
    }
}
