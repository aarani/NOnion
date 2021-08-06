using System;
using System.Text;
using System.Net;
using System.Reactive.Linq;
using System.Threading.Tasks;
using NOnion;
using NOnion.Cells;
using System.Threading;

namespace ConsoleApp1
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var file = System.IO.File.OpenWrite("test.txt");
            var guard = await TorGuard.NewClientAsTask(IPEndPoint.Parse("199.184.246.250:443"));
            var circuit = await TorCircuit.CreateFastAsTask(guard);
            Console.WriteLine("Created circuit, Id: {0}", circuit.Id);
            var key = new ManualResetEvent(false);
            var stream = await TorStream.CreateDirectoryStreamAsTask(circuit);
            string request = $"GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: 199.184.246.250\r\n\r\n";
            var requestBytes = Encoding.UTF8.GetBytes(request);
            await stream.SendAsTask(requestBytes);

            stream.DataReceived += (_, data) => file.Write(data, 0, data.Length);
            stream.StreamCompleted += (_, _) => {
                file.Flush();
                file.Close();
                key.Set();
            };

            key.WaitOne();
        }
    }
}
