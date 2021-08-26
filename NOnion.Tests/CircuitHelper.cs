using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.FSharp.Core;

using NOnion.Directory;
using NOnion.Http;
using NOnion.Network;
using NOnion.Utility;

namespace NOnion.Tests
{
    static internal class CircuitHelper
    {
        static private CircuitNodeDetail ConvertToCircuitNodeDetail(ServerDescriptorEntry server)
        {
            var fingerprintBytes = Hex.ToByteArray(server.Fingerprint.Value);
            var nTorOnionKeyBytes = Base64Util.FromString(server.NTorOnionKey.Value);
            var endpoint = IPEndPoint.Parse($"{server.Address.Value}:{server.OnionRouterPort.Value}");
            return new CircuitNodeDetail(endpoint, nTorOnionKeyBytes, fingerprintBytes);
        }

        //FIXME: SLOW
        static async internal Task<List<CircuitNodeDetail>> GetRandomRoutersForDirectoryBrowsing(int count = 1)
        {
            var fallbackDirectory = FallbackDirectorySelector.GetRandomFallbackDirectory();
            using TorGuard guard = await TorGuard.NewClientAsync(fallbackDirectory);
            TorCircuit circuit = new(guard);
            TorStream stream = new(circuit);

            await circuit.CreateAsync(FSharpOption<CircuitNodeDetail>.None);
            await stream.ConnectToDirectoryAsync();

            var httpClient = new TorHttpClient(stream, fallbackDirectory.Address.ToString());
            var serverDescriptors = ServerDescriptorsDocument.Parse(await httpClient.GetAsStringAsync("/tor/server/all", false));

            //Technically not all hops need to be directories but it doesn't matter in this context
            var suitableDirectories =
                    serverDescriptors
                    .Routers
                    .Where(
                        x =>
                            FSharpOption<string>.get_IsSome(x.NTorOnionKey) &&
                            FSharpOption<string>.get_IsSome(x.Fingerprint) &&
                            !x.Hibernating &&
                            FSharpOption<int>.get_IsSome(x.DirectoryPort) &&
                            x.DirectoryPort.Value != 0
                    );

            return
                suitableDirectories
                    .OrderBy(x => Guid.NewGuid())
                    .Take(count)
                    .Select(x => ConvertToCircuitNodeDetail(x))
                    .ToList();
        }
    }
}
