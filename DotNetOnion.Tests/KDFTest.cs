using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NOnion;
using NOnion.Utility;
using NOnion.Crypto.Kdf;
using NUnit.Framework;

namespace DotNetOnion.Tests
{
    public class KdfTest
    {
        [Test]
        public void LegacyKdfCalculationTest()
        {
            byte[] K0 = new byte[2 * Constants.HashLength];
            var kdfResult = Kdf.computeLegacyKdf(K0);

            var expectedKeyHandshake =
                Hex.ToByteArray("669B1C85ECBAFE23C999100F55A23E06BF59EAD7");
            var expectedForwardDigest =
                Hex.ToByteArray("CD0783158D334E6BDCF2D0F68C4B18EF5F579874");
            var expectedBackwardDigest =
                Hex.ToByteArray("F6E7194DD65C516A5805C4BA2311A7E6DA980A57");
            var expectedForwardKey =
                Hex.ToByteArray("7784611D3E42E10A6A5CB910A0008F2F");
            var expectedBackwardKey =
                Hex.ToByteArray("9F929A229295E4A053B24C6A2D70578F");

            CollectionAssert.AreEqual(kdfResult.KeyHandshake, expectedKeyHandshake);
            CollectionAssert.AreEqual(kdfResult.ForwardDigest, expectedForwardDigest);
            CollectionAssert.AreEqual(kdfResult.BackwardDigest, expectedBackwardDigest);
            CollectionAssert.AreEqual(kdfResult.ForwardKey, expectedForwardKey);
            CollectionAssert.AreEqual(kdfResult.BackwardKey, expectedBackwardKey);
        }
    }
}
