using DotNetOnion;
using System;
using System.Net;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        static async Task Main(string[] args)
        {
            TorGuard socket = new TorGuard(IPEndPoint.Parse("178.254.31.125:443"), "E767C3B8295AD79B02E80A21345C9F2B3C2AD7DB");
            await socket.ConnectAsync();
            
            Console.ReadKey();
        }
    }
}
