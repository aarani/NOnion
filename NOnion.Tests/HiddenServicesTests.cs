﻿using Microsoft.FSharp.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;
using Org.BouncyCastle.Crypto;

using NOnion.Network;
using NOnion.Http;
using NOnion.Cells.Relay;
using NOnion.Directory;
using Microsoft.FSharp.Collections;
using Org.BouncyCastle.Crypto.Parameters;

namespace NOnion.Tests
{
    public class HiddenServicesTests
    {
        /* It's possible that the router returned by GetRandomFallbackDirectory or
         * GetRandomRoutersForDirectoryBrowsing be inaccessable so we need to continue
         * retrying if an exceptions happened to make sure the issues are not related
         * to the router we randomly chose
         */
        private const int TestsRetryCount = 5;

        private async Task CreateIntroductionCircuit()
        {
            var node = (await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry()).First() as CircuitNodeDetail.Create;
            using TorGuard guard = await TorGuard.NewClientAsync(node.EndPoint);
            TorCircuit circuit = new(guard);

            await circuit.CreateAsync(CircuitNodeDetail.FastCreate);
            await circuit.RegisterAsIntroductionPointAsync(FSharpOption<AsymmetricCipherKeyPair>.None, FuncConvert.FromAction<RelayIntroduce>(StubCallback));
        }

        private void StubCallback(RelayIntroduce _)
        {

        }


        [Test]
        [Retry(TestsRetryCount)]
        public void CanCreateIntroductionCircuit()
        {
            Assert.DoesNotThrowAsync(CreateIntroductionCircuit);
        }


        private async Task CreateRendezvousCircuit()
        {
            var array = new byte[20];
            RandomNumberGenerator.Create().GetNonZeroBytes(array);

            var nodes = await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry(2);
            using TorGuard guard = await TorGuard.NewClientAsync((nodes[0] as CircuitNodeDetail.Create).EndPoint);
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

        [Test]
        [Retry(TestsRetryCount)]
        public async Task Test()
        {
            TorDirectory directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory());
            var (_, router) = await directory.GetRouterAsync(false);
            var host = new TorServiceHost();
            await host.CreateIntroductionPointAsync(router);
            var client = await TorServiceClient.CreateNewAsync(directory);
            byte[] PublicKey = { 0x8e, 0xca, 0xd, 0x2d, 0xe3, 0xb2, 0xc3, 0x51, 0xbb, 0xdb, 0xf6, 0x66, 0xf0, 0xc3, 0xa9, 0x1, 0x1e, 0x7d, 0x5e, 0xaa, 0xe, 0x8d, 0x81, 0x2a, 0x81, 0xbd, 0x9b, 0xae, 0x35, 0x7d, 0xf, 0x5f };
            await client.ConnectAsync(new (PublicKey, 0), host.Export().First().Value);
            await Task.Delay(-1);
        }
    }
}
