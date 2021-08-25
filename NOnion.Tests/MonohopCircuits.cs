using Microsoft.FSharp.Core;
using System;
using System.Diagnostics;
using System.Net;
using System.Linq;
using System.Threading.Tasks;

using NUnit.Framework;

using NOnion.Network;
using NOnion.Http;
using NOnion.Directory;
using NOnion.Utility;

namespace NOnion.Tests
{
    public class MonohopCircuits
    {

        private readonly IPEndPoint torServer = IPEndPoint.Parse("85.214.141.24:9001");

        [Test]
        public async Task CanCreateMonohopCircuit()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            TorCircuit circuit = new(guard);
            var circuitId = await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
            Debug.WriteLine("Created circuit, Id: {0}", circuitId);

            Assert.Greater(circuitId, 0);
        }

        [Test]
        public async Task CanCreateDirectoryStreamOverMonohopCircuit ()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            TorCircuit circuit = new(guard);
            TorStream stream = new(circuit);

            await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
            await stream.ConnectToDirectoryAsync();
        }

        [Test]
        public async Task CanReceiveConsensusOverMonohopCircuit()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            TorCircuit circuit = new(guard);
            TorStream stream = new(circuit);

            await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
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

            await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
            await stream.ConnectToDirectoryAsync();

            var httpClient = new TorHttpClient(stream, torServer.Address.ToString());
            var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", false);

            Assert.That(response.Contains("network-status-version"));
        }

        private async Task<ServerDescriptorEntry> GetRouter ()
        {
            using TorGuard guard = await TorGuard.NewClientAsync(torServer);
            TorCircuit circuit = new(guard);
            TorStream stream = new(circuit);

            await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
            await stream.ConnectToDirectoryAsync();

            var httpClient = new TorHttpClient(stream, torServer.Address.ToString());
            var serverDescriptors = ServerDescriptorsDocument.Parse(await httpClient.GetAsStringAsync("/tor/server/all", false));

            return serverDescriptors.Routers.First(x => FSharpOption<string>.get_IsSome(x.NTorOnionKey) && FSharpOption<string>.get_IsSome(x.Fingerprint) && FSharpOption<int>.get_IsSome(x.DirectoryPort) &&  x.DirectoryPort.Value != 0);
        }

        [Test]
        public async Task CanReceiveCompressedConsensusOverNonFastMonohopCircuit()
        {
            ServerDescriptorEntry server = null;
            try
            {
                server = await GetRouter();
            }
            catch
            {
                Assert.Inconclusive();
            }

            var fingerprintBytes = Hex.ToByteArray(server.Fingerprint.Value);
            var nTorOnionKeyBytes = Base64Util.FromString(server.NTorOnionKey.Value);
            var nodeDetail = new CircuitNodeDetail(nTorOnionKeyBytes, fingerprintBytes);

            using TorGuard guard = await TorGuard.NewClientAsync(IPEndPoint.Parse($"{server.Address.Value}:{server.OnionRouterPort.Value}"));
            TorCircuit circuit = new(guard);
            TorStream stream = new(circuit);

            await circuit.CreateAsync(nodeDetail);
            await stream.ConnectToDirectoryAsync();

            var httpClient = new TorHttpClient(stream, server.Address.Value);
            var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", false);

            Assert.That(response.Contains("network-status-version"));
        }
    }
}
