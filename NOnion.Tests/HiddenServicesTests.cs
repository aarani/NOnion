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

namespace NOnion.Tests
{
    public class HiddenServicesTests
    {
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
            TorCircuit circuit = new(guard);

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
            TorCircuit circuit = new(guard);

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

        public async Task EstablishAndCommunicateOverHSConnection()
        {
            byte[] publicKey = { 0x8e, 0xca, 0xd, 0x2d, 0xe3, 0xb2, 0xc3, 0x51, 0xbb, 0xdb, 0xf6, 0x66, 0xf0, 0xc3, 0xa9, 0x1, 0x1e, 0x7d, 0x5e, 0xaa, 0xe, 0x8d, 0x81, 0x2a, 0x81, 0xbd, 0x9b, 0xae, 0x35, 0x7d, 0xf, 0x5f };

            TorDirectory directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory());

            TorServiceHost host = new(directory, publicKey);
            await host.StartAsync();

            var serverSide =
                Task.Run(async () => {
                    var stream = await host.AcceptClientAsync();
                    await stream.SendDataAsync(Encoding.ASCII.GetBytes("Hi from hidden service!"));
                    await stream.EndAsync();
                });

            var clientSide =
                Task.Run(async () => {
                    var client = await TorServiceClient.ConnectAsync(directory, publicKey, host.Export().First().Value);
                    var stream = client.GetStream();
                    FSharpOption<byte[]> data;
                    using MemoryStream memStream = new();
                    while (!FSharpOption<byte[]>.get_IsNone(data = await stream.ReceiveAsync()))
                        memStream.Write(data.Value, 0, data.Value.Length);

                    CollectionAssert.AreEqual(memStream.ToArray(), Encoding.ASCII.GetBytes("Hi from hidden service!"));
                });


            await TaskUtils.WhenAllFailFast(serverSide, clientSide);
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanEstablishAndCommunicateOverHSConnection()
        {
            Assert.DoesNotThrowAsync(EstablishAndCommunicateOverHSConnection);
        }
    }
}

