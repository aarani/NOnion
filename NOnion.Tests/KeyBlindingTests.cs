﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NOnion.Crypto;
using NUnit.Framework;

namespace NOnion.Tests
{
    public class KeyBlindingTests
    {
        byte[] PublicKey = { 0x8e, 0xca, 0xd, 0x2d, 0xe3, 0xb2, 0xc3, 0x51, 0xbb, 0xdb, 0xf6, 0x66, 0xf0, 0xc3, 0xa9, 0x1, 0x1e, 0x7d, 0x5e, 0xaa, 0xe, 0x8d, 0x81, 0x2a, 0x81, 0xbd, 0x9b, 0xae, 0x35, 0x7d, 0xf, 0x5f };
        byte[] BlindingFactor = { 0x25, 0xf2, 0x45, 0x8e, 0xc4, 0xba, 0xd0, 0xd0, 0xed, 0xb4, 0x7f, 0x66, 0xa2, 0xee, 0x69, 0xc9, 0x6, 0xbb, 0xce, 0xe3, 0x1b, 0x73, 0x99, 0x10, 0x1e, 0x85, 0x38, 0xa8, 0xa4, 0x46, 0xf4, 0x28 };
        byte[] BlindedPublicKey = { 0x26, 0x73, 0x26, 0x48, 0x97, 0xe7, 0xeb, 0xca, 0xb1, 0x69, 0xea, 0x8f, 0x7b, 0x46, 0xa5, 0xbe, 0xfd, 0x1f, 0xdd, 0x44, 0x6e, 0x71, 0x8, 0x12, 0x60, 0x88, 0x13, 0x97, 0x5b, 0x4a, 0xa, 0x49
  };
        [Test]
        public void CheckBlindedPublicKey()
        {
            var computed = HiddenServicesCipher.CalculateBlindedPublicKey(BlindingFactor, PublicKey);
            CollectionAssert.AreEqual(computed, BlindedPublicKey);
        }
    }
}
