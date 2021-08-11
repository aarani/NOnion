using System;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using NOnion;
using Microsoft.FSharp.Core;

namespace ConsoleApp1
{
    class Program
    {
        static async Task Main(string[] args)
        {
            using TorGuard guard = await TorGuard.NewClientAsync(IPEndPoint.Parse("199.184.246.250:443"));
            using TorCircuit circuit = new (guard);
            using TorStream stream = new (circuit);

            var circuitId = await circuit.CreateFastAsync();
            Console.WriteLine("Created circuit, Id: {0}", circuitId);
            await stream.ConnectToDirectoryAsync();

            var request = $"GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: 199.184.246.250\r\n\r\n";
            var requestBytes = Encoding.UTF8.GetBytes(request);
            await stream.SendDataAsync(requestBytes);
            var response = await ReceiveAllAsString(stream);
            System.IO.File.WriteAllText("test.txt", response);
        }

        static async Task<string> ReceiveAllAsString(TorStream stream)
        {
            var result = string.Empty;
            var newMsg = await stream.ReceiveAsync();

            while (!FSharpOption<byte[]>.get_IsNone(newMsg))
            {
                result += Encoding.UTF8.GetString(newMsg.Value);
                newMsg = await stream.ReceiveAsync();
            }

            return result;
        }
    }
}
