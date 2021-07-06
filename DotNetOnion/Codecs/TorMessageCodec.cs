using DotNetOnion.Cells;
using DotNetOnion.Helpers;
using DotNetty.Codecs;
using DotNetty.Transport.Channels;
using NOnion.Cells;
using NOnion.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DotNetOnion.Codecs
{
    public class TorMessageCodec : MessageToMessageCodec<TorFrame, TorMessage>
    {
        protected override void Decode(IChannelHandlerContext ctx, TorFrame msg, List<object> output)
        {
            using MemoryStream payloadStream = new MemoryStream(msg.Payload);
            using BinaryReader payloadReader = new BinaryReader(payloadStream);
            var cell = CommandsHelper.GetCell(msg.Command, payloadReader);

            output.Add(new TorMessage
            {
                CircuitId = msg.CircuitId,
                Cell = cell
            });
        }

        protected override void Encode(IChannelHandlerContext ctx, TorMessage msg, List<object> output)
        {
            //TODO: better initial size ?
            using MemoryStream payloadStream = new MemoryStream(Constants.FixedPayloadLength);
            using BinaryWriter payloadWriter = new BinaryWriter(payloadStream);
            msg.Cell.Serialize(payloadWriter);

            // Check if the cell is fixed size for padding
            if (!CommandsHelper.IsVariableLength(msg.Cell.Command))
            {
                byte[] padding = new byte[Constants.FixedPayloadLength - payloadWriter.BaseStream.Position];
                payloadWriter.Write(padding);
            }

            output.Add(new TorFrame
            {
                CircuitId = msg.CircuitId,
                Command = msg.Cell.Command,
                Payload = payloadStream.ToArray()
            });
        }
    }
}
