using DotNetOnion;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        static async Task Main(string[] args)
        {
            TorGuard socket = new TorGuard(IPEndPoint.Parse("195.176.3.19:8443"), "BF1B662D1DA4E55F700C130AC58574B47FB7EB8E");
            await socket.ConnectAsync();
            TorCircuit circuit = 
                await TorCircuit.Create(socket, true);

            await circuit.SendRelayCell(new DotNetOnion.Cells.CellRelayPlain
            {
                Data = new byte[0],
                Digest = new byte[4],
                Recognized = 0,
                StreamId = 1,
                RelayCommand = DotNetOnion.Cells.RelayCommand.BEGIN_DIR
            });
            Console.ReadKey();
        }
    }
}
