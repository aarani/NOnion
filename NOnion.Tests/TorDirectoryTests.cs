using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

using NOnion;
using NOnion.Directory;
using NOnion.Network;

namespace NOnion.Tests
{
    public class TorDirectoryTests
    {
        /* It's possible that the router returned by GetRandomFallbackDirectory be inaccessable
         * so we need to continue retrying if an exceptions happened to make sure the issues are
         * not related to the router we randomly chose
         */
        private const int TestRetryCount = 5;

        private async Task BootstrapTorDirectory()
        {
            await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory());
        }

        [Test]
        [Retry(TestRetryCount)]
        public void CanBootstrapTorDirectory()
        {
            Assert.DoesNotThrowAsync(BootstrapTorDirectory);
        }

        private async Task ReturnRandomRouter()
        {
            TorDirectory directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory());
            var (endpoint, router) = await directory.GetRouterAsync(true);
            Assert.IsTrue(router.IsCreate);
            Assert.IsFalse((router as CircuitNodeDetail.Create).IdentityKey.All(x => x == 0));
            Assert.IsFalse((router as CircuitNodeDetail.Create).NTorOnionKey.All(x => x == 0));
            Assert.IsNotNull((router as CircuitNodeDetail.Create).EndPoint);
        }

        [Test]
        [Retry(TestRetryCount)]
        public void CanReturnRandomRouter()
        {
            Assert.DoesNotThrowAsync(ReturnRandomRouter);
        }
    }
}
