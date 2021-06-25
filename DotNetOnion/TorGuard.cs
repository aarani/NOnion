using DotNetOnion.Cells;
using DotNetOnion.ChannelHandlers;
using DotNetOnion.Codecs;
using DotNetOnion.Helpers;
using DotNetty.Common.Concurrency;
using DotNetty.Common.Utilities;
using DotNetty.Handlers.Tls;
using DotNetty.Transport.Bootstrapping;
using DotNetty.Transport.Channels;
using DotNetty.Transport.Channels.Sockets;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DotNetOnion
{
    public class TorGuard : IDisposable
    {
        private readonly IPEndPoint endpoint;
        private readonly string fingerprint;
        private readonly TaskCompletionSource closeCompletionSource;
        private readonly TorChannelHandler handler;
        IEventLoopGroup eventLoopGroup;
        IChannel channel;
        public delegate void CircuitDataReceived (Cell cell);

        public Dictionary<ushort, CircuitDataReceived> CircuitDataHandlers = new ();
        public TorGuard(IPEndPoint endpoint, string fingerprint)
        {
            this.endpoint = endpoint;
            this.fingerprint = fingerprint;

            closeCompletionSource = new TaskCompletionSource();
            handler = new(false);
        }

        public async Task<bool> ConnectAsync(int threadCount = 1, CancellationToken token = default)
        {
            try
            {
                eventLoopGroup = new MultithreadEventLoopGroup(threadCount);

                handler.DataReceived += Handler_DataReceived;

                Bootstrap bootstrap = new();
                bootstrap
                    .Group(eventLoopGroup)
                    .Channel<TcpSocketChannel>()
                    .Option(ChannelOption.SoKeepalive, true)
                    .Handler(new ActionChannelInitializer<ISocketChannel>(channel => {
                        var pipeline = channel.Pipeline;

                        ClientTlsSettings settings = new(SslProtocols.Tls12, false, new(), "");
                        pipeline.AddLast(new TlsHandler(stream => new SslStream(stream, true, (sender, certificate, chain, errors) => true), settings));
                        pipeline.AddLast(new TorFrameDecoder(), new TorFrameEncoder());
                        pipeline.AddLast(new TorMessageCodec());
                        pipeline.AddLast(handler);
                    }));

                channel = await bootstrap.ConnectAsync(endpoint);
                channel.CloseCompletion.LinkOutcome(closeCompletionSource);

                token.Register(CloseAsync);

                await handler.HandshakeCompleted;

                return true;
            }
            catch
            {
                //TODO: log
                CloseAsync();
                return false;
            }
        }

        private async Task Send (ushort circuitId, Cell cell)
        {
            await channel.WriteAndFlushAsync(new TorMessage
            {
                Cell = cell,
                CircuitId = circuitId
            });
        }

        private void Handler_DataReceived(TorMessage torMessage)
        {
            if (CircuitDataHandlers.TryGetValue(torMessage.CircuitId, out var handler))
            {
                //TODO: should this happen in separate thread?
                handler.Invoke(torMessage.Cell);
            }

            Console.WriteLine($"Orphan message with CircuitId = {torMessage.CircuitId} Command = {torMessage.Cell.GetType()}");
        }
        private async void CloseAsync()
        {
            try
            {
                if (channel != null)
                {
                    await channel.CloseAsync();
                }
                if (eventLoopGroup != null)
                {
                    await eventLoopGroup.ShutdownGracefullyAsync();
                }
            }
            finally
            {
                closeCompletionSource.TryComplete();
            }
        }

        public void Dispose()
        {
            handler.DataReceived -= Handler_DataReceived;
            CloseAsync();
        }
    }
}
