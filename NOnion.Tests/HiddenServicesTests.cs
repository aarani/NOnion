using Microsoft.FSharp.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;

using NUnit.Framework;
using Org.BouncyCastle.Crypto;

using NOnion.Network;
using NOnion.Http;
using NOnion.Cells.Relay;
using NOnion.Directory;
using NOnion.Tests.Utility;
using NOnion.Services;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using NUnit.Framework.Internal;
using System.Diagnostics;

namespace NOnion.Tests
{
    public class HiddenServicesTests
    {
        [SetUp]
        public void Init()
        {
            TorLogger.Init(TestContext.Progress.WriteLine);
        }

        /* It's possible that the router returned by GetRandomFallbackDirectory or
         * GetRandomRoutersForDirectoryBrowsing be inaccessable so we need to continue
         * retrying if an exceptions happened to make sure the issues are not related
         * to the router we randomly chose
         */
        private const int TestsRetryCount = 10;

        private async Task CreateIntroductionCircuit()
        {
            var node = (CircuitNodeDetail.Create)(await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry()).First();
            using TorGuard guard = await TorGuard.NewClientAsync(node.EndPoint);
            var circuit = new TorCircuit(guard);

            await circuit.CreateAsync(CircuitNodeDetail.FastCreate);
            await circuit.RegisterAsIntroductionPointAsync(FSharpOption<AsymmetricCipherKeyPair>.None, StubCallback);
        }

        private Task StubCallback(RelayIntroduce _)
        {
            return Task.CompletedTask;
        }


        [Test]
        [Retry(TestsRetryCount)]
        public void CanCreateIntroductionCircuit()
        {
            Assert.DoesNotThrowAsync(CreateIntroductionCircuit);
        }


        private async Task CreateRendezvousCircuit()
        {
            var array = new byte[Constants.RendezvousCookieLength];
            RandomNumberGenerator.Create().GetNonZeroBytes(array);

            var nodes = await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry(2);
            using TorGuard guard = await TorGuard.NewClientAsync(((CircuitNodeDetail.Create)nodes[0]).EndPoint);
            var circuit = new TorCircuit(guard);

            await circuit.CreateAsync(nodes[0]);
            await circuit.ExtendAsync(nodes[1]);
            await circuit.RegisterAsRendezvousPointAsync(array);
        }


        [Test]
        [Retry(TestsRetryCount)]
        public void CanCreateRendezvousCircuit()
        {
            Assert.DoesNotThrowAsync(CreateRendezvousCircuit);
        }

        private async Task<int> ReadExact(TorStream stream, byte[] buffer, int off, int len)
        {
            if (len - off <= 0) return 0;

            var bytesRead = await stream.ReceiveAsync(buffer, off, len - off);

            if (bytesRead == 0 || bytesRead == -1)
                throw new Exception("Not enough data");

            return bytesRead + await ReadExact(stream, buffer, off + bytesRead, len);
        }

        public async Task BrowseFacebookOverHS()
        {
            TorDirectory directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory());

            var client = await TorServiceClient.ConnectAsync(directory, TorServiceDescriptors.NewOnionURL("facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion"));
            var httpClient = new TorHttpClient(client.GetStream(), "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion");
            await httpClient.GetAsStringAsync("/", false);
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanBrowseFacebookOverHS()
        {
            Assert.ThrowsAsync(typeof(UnsuccessfulHttpRequestException), BrowseFacebookOverHS);
        }

        public async Task EstablishAndCommunicateOverHSConnectionOnionStyle()
        {
            TorDirectory directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory());
 
            TorLogger.Log("Finished bootstraping");

            var kpGen = new Ed25519KeyPairGenerator();
            var random = new SecureRandom();
            kpGen.Init(new Ed25519KeyGenerationParameters(random));
            var masterKey = kpGen.GenerateKeyPair();

            var host = new TorServiceHost(directory, TestsRetryCount, masterKey);
            await host.StartAsync();

            TorLogger.Log("Finished starting HS host");

            var dataToSendAndReceive = new byte[] { 1, 2, 3, 4 };

            var serverSide =
                Task.Run(async () => {
                    var stream = await host.AcceptClientAsync();
                    var bytesToSendWithLength = BitConverter.GetBytes(dataToSendAndReceive.Length).Concat(dataToSendAndReceive).ToArray();
                    await stream.SendDataAsync(bytesToSendWithLength);
                    await stream.EndAsync();
                });

            var clientSide =
                Task.Run(async () => {
                    var client = await TorServiceClient.ConnectAsync(directory, TorServiceDescriptors.NewOnionURL(host.ExportUrl()));
                    var stream = client.GetStream();
                    var lengthBytes = new byte[sizeof(int)];
                    await ReadExact(stream, lengthBytes, 0, lengthBytes.Length);
                    var length = BitConverter.ToInt32(lengthBytes);
                    var buffer = new byte[length];
                    await ReadExact(stream, buffer, 0, buffer.Length);

                    CollectionAssert.AreEqual(buffer, dataToSendAndReceive);
                });

            await TaskUtils.WhenAllFailFast(serverSide, clientSide);
        }
        
        [Test]
        [Retry(TestsRetryCount)]
        public void CanEstablishAndCommunicateOverHSConnectionOnionStyle()
        {
            Assert.DoesNotThrowAsync(EstablishAndCommunicateOverHSConnectionOnionStyle);
        }    
    }
}

