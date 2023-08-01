using System;
using System.IO;
using System.Threading.Tasks;

using NUnit.Framework;

using NOnion.Directory;
using NOnion.Http;
using NOnion.Network;

namespace NOnion.Tests
{
    internal class OutsideWorldConnectionTest
    {
        /* It's possible that the router returned by GetRandomFallbackDirectory or
         * GetRandomRoutersForDirectoryBrowsing be inaccessable so we need to continue
         * retrying if an exceptions happened to make sure the issues are not related
         * to the router we randomly chose
         */
        private const int TestsRetryCount = 10;

        private async Task BrowseGoogle()
        {
            var directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory(), new DirectoryInfo(Path.GetTempPath()));
            var (guardEndPoint, guardRouter) = await directory.GetRouterAsync(RouterType.Guard);
            var (_, middleRouter) = await directory.GetRouterAsync(RouterType.Normal);
            var (_, exitRouter) = await directory.GetRouterAsync(RouterType.Exit);

            var guard = await TorGuard.NewClientAsync(guardEndPoint);
            var circuit = new TorCircuit(guard);
            await circuit.CreateAsync(guardRouter);
            await circuit.ExtendAsync(middleRouter);
            await circuit.ExtendAsync(exitRouter);

            TorStream stream = new TorStream(circuit);
            await stream.ConnectToOutsideAsync("google.com", 80);

            TorHttpClient httpClient = new TorHttpClient(stream, "google.com");
            await httpClient.GetAsStringAsync("/", false);
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanBrowseGoogle()
        {
            Assert.ThrowsAsync(typeof(UnsuccessfulHttpRequestException), BrowseGoogle);
        }
    }
}
