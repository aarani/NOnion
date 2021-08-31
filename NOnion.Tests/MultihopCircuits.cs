using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

using NUnit.Framework;

using NOnion.Network;
using NOnion.Http;

namespace NOnion.Tests
{
    public class MultihopCircuits
    {

        [Test]
        public async Task CanCreateMultiHopCircuits()
        {
            TestContext.Progress.WriteLine("Receiving descriptors...");
            List<CircuitNodeDetail> nodes = null;
            try
            {
                nodes = await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry(3);
            }
            catch
            {
                Assert.Inconclusive();
            }


            TestContext.Progress.WriteLine($"Connecting to {nodes[0].Address.Value.Address}...");
            using TorGuard guard = await TorGuard.NewClientAsync(nodes[0].Address.Value);
            TorCircuit circuit = new(guard);

            TestContext.Progress.WriteLine("Creating the circuit...");
            await circuit.CreateAsync(nodes[0]);
            TestContext.Progress.WriteLine($"Extending the circuit to {nodes[1].Address.Value.Address}...");
            await circuit.ExtendAsync(nodes[1]);
            TestContext.Progress.WriteLine($"Extending the circuit to {nodes[2].Address.Value.Address}...");
            await circuit.ExtendAsync(nodes[2]);

            TestContext.Progress.WriteLine("Creating the stream...");
            TorStream stream = new(circuit);
            await stream.ConnectToDirectoryAsync();

            TestContext.Progress.WriteLine("Sending http request over multihop circuit...");
            var httpClient = new TorHttpClient(stream, nodes[2].Address.Value.Address.ToString());
            var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", false);

            Assert.That(response.Contains("network-status-version"));
        }

    }
}
