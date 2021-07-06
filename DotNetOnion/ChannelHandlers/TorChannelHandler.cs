using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DotNetOnion.Cells;
using DotNetOnion.Codecs;
using DotNetOnion.Helpers;
using DotNetty.Common.Concurrency;
using DotNetty.Common.Utilities;
using DotNetty.Handlers;
using DotNetty.Transport.Channels;
using static NOnion.Cells.CellNetInfo;
using NOnion.Cells;

namespace DotNetOnion.ChannelHandlers
{
    public class TorChannelHandler : ChannelDuplexHandler
    {

        private readonly TaskCompletionSource completionSource;
        private readonly HandshakeResult handshakeState = new HandshakeResult();

        public delegate void ChannelDataReceived(TorMessage torMessage);

        public event ChannelDataReceived DataReceived;

        private readonly bool authentication;

        public TorChannelHandler(bool authentication)
        {
            this.authentication = authentication;
            completionSource = new TaskCompletionSource();
        }

        public Task HandshakeCompleted => completionSource.Task;

        public override void ChannelActive(IChannelHandlerContext context)
        {
            base.ChannelActive(context);
            StartHandshake(context);
        }

        private void StartHandshake(IChannelHandlerContext context)
        {
            context.WriteAndFlushAsync(
                    new TorMessage
                    {
                        CircuitId = 0,
                        Cell = new CellVersions() { Versions = Constants.SupportedVersion.ToList() }
                    }
                );
        }

        public override void ChannelRead(IChannelHandlerContext context, object message)
        {
            base.ChannelRead(context, message);

            if (handshakeState.GetStatus() != HandshakeResult.Status.Completed)
            {
                ReceiveServerHandshakeData(context, (TorMessage)message);
            }
            else
            {
                DataReceived?.Invoke((TorMessage)message);
            }
        }

        private void ReceiveServerHandshakeData(IChannelHandlerContext context, TorMessage message)
        {
            switch (message.Cell)
            {
                case CellVersions version:
                    HandleVersion(version);
                    return;
                case CellCerts certs:
                    HandleCerts(certs);
                    return;
                case CellAuthChallenge authChallengeCell:
                    HandleAuthChallenge(authChallengeCell);
                    return;
                case CellNetInfo netInfoCell:
                    HandleNetInfo(context, netInfoCell);
                    return;
            }
        }

        private void HandleNetInfo(IChannelHandlerContext context, CellNetInfo netInfoCell)
        {
            if (handshakeState.GetStatus() != HandshakeResult.Status.WaitingForNetInfo)
                throw new Exception("WTF!");

            handshakeState.NetInfo = netInfoCell;

            // We have enough data to complete the handshake
            CompleteHandshake(context);
        }

        private void CompleteHandshake(IChannelHandlerContext context)
        {
            if (!authentication)
            {
                context.WriteAndFlushAsync(
                    new TorMessage
                    {
                        CircuitId = 0,
                        Cell = new CellNetInfo()
                        {
                            MyAddresses = new List<RouterAddress> { handshakeState.NetInfo.OtherAddress }, //TODO: DO NOT TRUST THIS
                            OtherAddress = handshakeState.NetInfo.MyAddresses.First(), //TODO: CHECK THIS!!!
                            Time = DateTime.UtcNow.ToUnixTimestamp()
                        }
                    }
                ).ContinueWith((_) => completionSource.TryComplete(), TaskContinuationOptions.OnlyOnRanToCompletion | TaskContinuationOptions.ExecuteSynchronously);
                
            }
            else
                throw new NotImplementedException();
        }

        private void HandleVersion(CellVersions version)
        {
            if (handshakeState.GetStatus() != HandshakeResult.Status.WaitingForVersions)
                throw new Exception("//FIXME");

            handshakeState.Versions = version;
        }

        private void HandleCerts(CellCerts certs)
        {
            if (handshakeState.GetStatus() != HandshakeResult.Status.WaitingForCerts)
                throw new Exception("//FIXME");

            handshakeState.Certs = certs;
        }

        private void HandleAuthChallenge(CellAuthChallenge authChallengeCell)
        {
            if (handshakeState.GetStatus() != HandshakeResult.Status.WaitingForAuthChallenge)
                throw new Exception("//FIXME");

            handshakeState.AuthChallenge = authChallengeCell;
        }

        public override void ChannelInactive(IChannelHandlerContext context)
        {
            base.ChannelInactive(context);
        }

        public override void ExceptionCaught(IChannelHandlerContext context, Exception exception)
        {
            base.ExceptionCaught(context, exception);
        }
    }
}
