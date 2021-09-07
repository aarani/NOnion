using Microsoft.FSharp.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;

using NOnion.Network;
using NOnion.Http;


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
            var node = (await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry()).First();
            using TorGuard guard = await TorGuard.NewClientAsync(node.Address.Value);
            TorCircuit circuit = new(guard);

            await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
            await circuit.RegisterAsIntroductionPointAsync();
        }


        [Test]
        [Retry(TestsRetryCount)]
        public void CanCreateIntroductionCircuit ()
        {
            Assert.DoesNotThrowAsync(CreateIntroductionCircuit);
        }
    }
}
