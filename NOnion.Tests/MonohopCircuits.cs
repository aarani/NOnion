using Microsoft.FSharp.Core;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;

using NOnion.Network;
using NOnion.Http;

namespace NOnion.Tests
{
    public class MonohopCircuits
    {

        private readonly IPEndPoint torServer = IPEndPoint.Parse("199.184.246.250:443");

        [Test]
        public async Task CanCreateMonohopCircuit()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            TorCircuit circuit = new(guard);
            var circuitId = await circuit.CreateFastAsync();
            Debug.WriteLine("Created circuit, Id: {0}", circuitId);

            Assert.Greater(circuitId, 0);
        }

        [Test]
        public async Task CanCreateDirectoryStreamOverMonohopCircuit ()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            TorCircuit circuit = new(guard);
            TorStream stream = new(circuit);

            await circuit.CreateFastAsync();
            await stream.ConnectToDirectoryAsync();
        }

        [Test]
        public async Task CanReceiveConsensusOverMonohopCircuit()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            TorCircuit circuit = new(guard);
            TorStream stream = new(circuit);

            await circuit.CreateFastAsync();
            await stream.ConnectToDirectoryAsync();

            var httpClient = new TorHttpClient(stream, torServer.Address.ToString());
            var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", true);

            Assert.That(response.Contains("network-status-version"));
        }

        [Test]
        public async Task CanReceiveCompressedConsensusOverMonohopCircuit()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            TorCircuit circuit = new(guard);
            TorStream stream = new(circuit);

            await circuit.CreateFastAsync();
            await stream.ConnectToDirectoryAsync();

            var httpClient = new TorHttpClient(stream, torServer.Address.ToString());
            var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", false);

            Assert.That(response.Contains("network-status-version"));
        }

    }
}
