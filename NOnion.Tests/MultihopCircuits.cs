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
        // Our circuit creation process does not have a timeout which causes the process
        // to wait forever for a response which in our CI causes the run to go on for
        // hours until Github force kills the run.
        // So we add a 3 mins timeout on this test since most successful runs take less than that.
        [Timeout(180_000)]
        public async Task CanCreateMultiHopCircuits()
        {
            Debug.WriteLine("Receiving descriptors...");
            List<CircuitNodeDetail> nodes = null;
            try
            {
                nodes = await CircuitHelper.GetRandomRoutersForDirectoryBrowsing(3);
            }
            catch
            {
                Assert.Inconclusive();
            }


            Debug.WriteLine($"Connceting to {nodes[0].Address.Value.Address}...");
            using TorGuard guard = await TorGuard.NewClientAsync(nodes[0].Address.Value);
            TorCircuit circuit = new(guard);

            Debug.WriteLine("Creating the circuit...");
            await circuit.CreateAsync(nodes[0]);
            Debug.WriteLine($"Extending the circuit to {nodes[1].Address.Value.Address}...");
            await circuit.ExtendAsync(nodes[1]);
            Debug.WriteLine($"Extending the circuit to {nodes[2].Address.Value.Address}...");
            await circuit.ExtendAsync(nodes[2]);

            Debug.WriteLine("Creating the stream...");
            TorStream stream = new(circuit);
            await stream.ConnectToDirectoryAsync();

            Debug.WriteLine("Sending http request over multihop circuit...");
            var httpClient = new TorHttpClient(stream, nodes[2].Address.Value.Address.ToString());
            var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", false);

            Assert.That(response.Contains("network-status-version"));
        }

    }
}
