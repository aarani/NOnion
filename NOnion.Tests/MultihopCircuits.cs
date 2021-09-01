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
        /* It's possible that the router returned by GetRandomFallbackDirectory or
         * GetRandomRoutersForDirectoryBrowsing be inaccessable so we need to continue
         * retrying if an exceptions happened to make sure the issues are not related
         * to the router we randomly chose
         */
        private const int TestRetryCount = 5;

        private async Task CreateMultiHopCircuits()
        {
            TestContext.Progress.WriteLine("Receiving descriptors...");
            List<CircuitNodeDetail> nodes = await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry(3);

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

        [Test]
        [Retry(TestRetryCount)]
        public void CanCreateMultiHopCircuits()
        {
            Assert.DoesNotThrowAsync(CreateMultiHopCircuits);
        }

    }
}
