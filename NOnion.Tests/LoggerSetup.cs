using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;

namespace NOnion.Tests
{
    [SetUpFixture]
    public class LoggerSetup
    {
        [OneTimeSetUp]
        public void Init()
        {
            TorLogger.Init(TestContext.Progress.WriteLine);
        }
    }
}
