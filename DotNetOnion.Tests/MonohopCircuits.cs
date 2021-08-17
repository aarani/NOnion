using Microsoft.FSharp.Core;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;

using NOnion;

namespace DotNetOnion.Tests
{
    public class MonohopCircuits
    {

        private readonly IPEndPoint torServer = IPEndPoint.Parse("199.184.246.250:443");

        [Test]
        public async Task CanCreateMonohopCircuit()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            using TorCircuit circuit = new(guard);
            var circuitId = await circuit.CreateFastAsync();
            Debug.WriteLine("Created circuit, Id: {0}", circuitId);

            Assert.Greater(circuitId, 0);
        }

        [Test]
        public async Task CanCreateDirectoryStreamOverMonohopCircuit ()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            using TorCircuit circuit = new(guard);
            using TorStream stream = new(circuit);

            await circuit.CreateFastAsync();
            await stream.ConnectToDirectoryAsync();
        }

        [Test]
        public async Task CanReceiveConsensusOverMonohopCircuit()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            using TorCircuit circuit = new(guard);
            using TorStream stream = new(circuit);

            await circuit.CreateFastAsync();
            await stream.ConnectToDirectoryAsync();

            var request = $"GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: 199.184.246.250\r\n\r\n";
            var requestBytes = Encoding.UTF8.GetBytes(request);
            await stream.SendDataAsync(requestBytes);

            var response = string.Empty;
            var newPartialResponse = await stream.ReceiveAsync();

            while (!FSharpOption<byte[]>.get_IsNone(newPartialResponse))
            {
                response += Encoding.UTF8.GetString(newPartialResponse.Value);
                newPartialResponse = await stream.ReceiveAsync();
            }

            Assert.That(response.Contains("network-status-version"));
        }
    }
}
