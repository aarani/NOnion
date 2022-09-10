using System.IO;
using System.Linq;

using NUnit.Framework;
using Newtonsoft.Json;

using NOnion.Directory;
using Microsoft.FSharp.Core;

namespace NOnion.Tests
{
    public class DirectoryParsers
    {
        [Test]
        public void CanParseNetworkStatusDocumentAndConvertToJson ()
        {
            // Tor directory spec enforces documents to use \n (The ascii LF character (hex value 0x0a)
            var networkStatusStr = File.ReadAllText($"Directory-Samples{Path.DirectorySeparatorChar}NetworkStatus.txt").Replace("\r\n","\n");
            var expectedNetworkStatusJson = File.ReadAllText($"Directory-Samples{Path.DirectorySeparatorChar}NetworkStatus.json");

            NetworkStatusDocument networkStatus = NetworkStatusDocument.Parse(networkStatusStr);
            var count = networkStatus.Routers.Where(x => FSharpOption<int>.get_IsSome(x.DirectoryPort) && x.DirectoryPort.Value > 0).Count();
            var networkStatusJson = JsonConvert.SerializeObject(networkStatus);

            Assert.That(networkStatusJson, Is.EqualTo(expectedNetworkStatusJson));
        }

        [Test]
        public void CanParseServerDescriptorsDocumentAndConvertToJson()
        {
            // Tor directory spec enforces documents to use \n (The ascii LF character (hex value 0x0a)
            var serverDescriptorsStr = File.ReadAllText($"Directory-Samples{Path.DirectorySeparatorChar}ServerDescriptors.txt").Replace("\r\n", "\n");
            var expectedServerDescriptorsJson = File.ReadAllText($"Directory-Samples{Path.DirectorySeparatorChar}ServerDescriptors.json");

            ServerDescriptorsDocument serverDescriptors = ServerDescriptorsDocument.Parse(serverDescriptorsStr);
            var serverDescriptorsJson = JsonConvert.SerializeObject(serverDescriptors);

            Assert.That(serverDescriptorsJson, Is.EqualTo(expectedServerDescriptorsJson));
        }

        [Test]
        public void CanParseHiddenServiceFirstLayerDescriptorDocument()
        {
            // Tor directory spec enforces documents to use \n (The ascii LF character (hex value 0x0a)
            var str = File.ReadAllText($"Directory-Samples{Path.DirectorySeparatorChar}test.txt").Replace("\r\n", "\n");
            HiddenServiceFirstLayerDescriptorDocument test = HiddenServiceFirstLayerDescriptorDocument.Parse(str);
            Assert.AreEqual(test.ToString(), str);
        }
    }
}
