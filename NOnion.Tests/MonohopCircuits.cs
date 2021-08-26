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
        private const int TestRetryLimit = 5;

        [Test]
        public async Task CanCreateMonohopCircuit()
        {
            Exception lastException = null;

            int retryCount = 0;
            while (retryCount < TestRetryLimit)
            {
                try
                {
                    IPEndPoint fallbackDirectory = FallbackDirectorySelector.GetRandomFallbackDirectory();
                    using TorGuard guard = await TorGuard.NewClientAsync(fallbackDirectory);
                    TorCircuit circuit = new(guard);
                    var circuitId = await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
                    TestContext.Progress.WriteLine("Created circuit, Id: {0}", circuitId);

                    Assert.Greater(circuitId, 0);
                    return;
                }
                catch (GuardConnectionFailedException ex)
                {
                    lastException = ex;
                    retryCount++;
                    continue;
                }
            }

            throw lastException;
        }

        [Test]
        public async Task CanCreateDirectoryStreamOverMonohopCircuit()
        {
            Exception lastException = null;

            int retryCount = 0;
            while (retryCount < TestRetryLimit)
            {
                try
                {
                    IPEndPoint fallbackDirectory = FallbackDirectorySelector.GetRandomFallbackDirectory();
                    using TorGuard guard = await TorGuard.NewClientAsync(fallbackDirectory);
                    TorCircuit circuit = new(guard);
                    TorStream stream = new(circuit);

                    await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
                    await stream.ConnectToDirectoryAsync();
                    return;
                }
                catch (GuardConnectionFailedException ex)
                {
                    lastException = ex;
                    retryCount++;
                    continue;
                }
            }

            throw lastException;
        }

        [Test]
        public async Task CanReceiveConsensusOverMonohopCircuit()
        {
            Exception lastException = null;

            int retryCount = 0;
            while (retryCount < TestRetryLimit)
            {
                try
                {
                    IPEndPoint fallbackDirectory = FallbackDirectorySelector.GetRandomFallbackDirectory();
                    using TorGuard guard = await TorGuard.NewClientAsync(fallbackDirectory);
                    TorCircuit circuit = new(guard);
                    TorStream stream = new(circuit);

                    await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
                    await stream.ConnectToDirectoryAsync();

                    var httpClient = new TorHttpClient(stream, fallbackDirectory.Address.ToString());
                    var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", true);

                    Assert.That(response.Contains("network-status-version"));
                    return;
                }
                catch (GuardConnectionFailedException ex)
                {
                    lastException = ex;
                    retryCount++;
                    continue;
                }
            }

            throw lastException;
        }

        [Test]
        public async Task CanReceiveCompressedConsensusOverMonohopCircuit()
        {
            Exception lastException = null;

            int retryCount = 0;
            while (retryCount < TestRetryLimit)
            {
                try
                {
                    IPEndPoint fallbackDirectory = FallbackDirectorySelector.GetRandomFallbackDirectory();
                    using TorGuard guard = await TorGuard.NewClientAsync(fallbackDirectory);
                    TorCircuit circuit = new(guard);
                    TorStream stream = new(circuit);

                    await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
                    await stream.ConnectToDirectoryAsync();

                    var httpClient = new TorHttpClient(stream, fallbackDirectory.Address.ToString());
                    var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", false);

                    Assert.That(response.Contains("network-status-version"));
                    return;
                }
                catch (GuardConnectionFailedException ex)
                {
                    lastException = ex;
                    retryCount++;
                    continue;
                }
            }

            throw lastException;
        }

        [Test]
        public async Task CanReceiveCompressedConsensusOverNonFastMonohopCircuit()
        {
            var node = (await CircuitHelper.GetRandomRoutersForDirectoryBrowsing()).First();

            Exception lastException = null;

            int retryCount = 0;
            while (retryCount < TestRetryLimit)
            {
                try
                {
                    using TorGuard guard = await TorGuard.NewClientAsync(node.Address.Value);
                    TorCircuit circuit = new(guard);
                    TorStream stream = new(circuit);

                    await circuit.CreateAsync(node);
                    await stream.ConnectToDirectoryAsync();

                    var httpClient = new TorHttpClient(stream, node.Address.Value.Address.ToString());
                    var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", false);

                    Assert.That(response.Contains("network-status-version"));
                    return;
                }
                catch (GuardConnectionFailedException ex)
                {
                    lastException = ex;
                    retryCount++;
                    continue;
                }
            }

            throw lastException;
        }
    }
}
