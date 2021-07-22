using System;
using System.Text;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using NOnion;

namespace ConsoleApp1
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var file = System.IO.File.OpenWrite("test.txt");
            var guard = await TorGuard.NewClientAsync(IPEndPoint.Parse("199.184.246.250:443"));
            var circuit = await TorCircuit.CreateFastAsync(guard);
            Console.WriteLine("Created circuit, Id: {0}", circuit.Id);

            TaskCompletionSource<long> dataReceivedCompletion = new ();

            var stream = await TorStream.CreateDirectoryStreamAsync(circuit);
            stream.DataReceived += (_, data) => file.Write(data, 0, data.Length);
            stream.StreamCompleted += (_, _) => {
                file.Flush();
                file.Close();
                dataReceivedCompletion.SetResult(file.Position);
            };

            var request = $"GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: 199.184.246.250\r\n\r\n";
            var requestBytes = Encoding.UTF8.GetBytes(request);
            await stream.SendAsync(requestBytes);

            var size = await dataReceivedCompletion.Task;
            Console.WriteLine("Received data size: {0}", size);
        }
    }
}
