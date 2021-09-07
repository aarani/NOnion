using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using NUnit.Framework;

using NOnion.Network;
using NOnion.Http;

namespace NOnion.Tests
{
    public class MultihopCircuits
    {
        public MultihopCircuits()
        {
            Console.SetOut(TestContext.Progress);
        }

        /* It's possible that the router returned by GetRandomFallbackDirectory or
         * GetRandomRoutersForDirectoryBrowsing be inaccessable so we need to continue
         * retrying if an exceptions happened to make sure the issues are not related
         * to the router we randomly chose
         */
        private const int TestRetryCount = 5;

        private async Task CreateMultiHopCircuits()
        {
            Console.WriteLine("Receiving descriptors...");
            List<CircuitNodeDetail> nodes = await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry(3);

            Console.WriteLine($"Connecting to {nodes[0].Address.Value.Address}...");
            using TorGuard guard = await TorGuard.NewClientAsync(nodes[0].Address.Value);
            TorCircuit circuit = new(guard);

            Console.WriteLine("Creating the circuit...");
            await circuit.CreateAsync(nodes[0]);
            Console.WriteLine($"Extending the circuit to {nodes[1].Address.Value.Address}...");
            await circuit.ExtendAsync(nodes[1]);
            Console.WriteLine($"Extending the circuit to {nodes[2].Address.Value.Address}...");
            await circuit.ExtendAsync(nodes[2]);

            Console.WriteLine("Creating the stream...");
            TorStream stream = new(circuit);
            await stream.ConnectToDirectoryAsync();

            Console.WriteLine("Sending http request over multihop circuit...");
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
