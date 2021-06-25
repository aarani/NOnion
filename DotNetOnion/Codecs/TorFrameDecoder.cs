using DotNetOnion.Helpers;
using DotNetty.Buffers;
using DotNetty.Codecs;
using DotNetty.Transport.Channels;
using System;
using System.Collections.Generic;
using System.Text;

namespace DotNetOnion.Codecs
{
    internal class TorFrameDecoder : ByteToMessageDecoder
    {
        //TODO(Performance): read and save as you get instead of reverting back to start everytime we don't have enough data
        protected override void Decode(IChannelHandlerContext context, IByteBuffer input, List<object> output)
        {
            // make sure packet header is received already (circuitId & command)
            if (input.ReadableBytes < 3)
                return;

            input.MarkReaderIndex();
            var circuitId = input.ReadUnsignedShort();
            var command = input.ReadByte();

            int length;
            // If command is fixed size the rest of the packet should be 509 bytes
            if (CommandsHelper.IsVariableLength(command))
            {
                // not enough bytes to understand the length of the message
                if (input.ReadableBytes < 2)
                {
                    input.ResetReaderIndex();
                    return;
                }

                length = input.ReadUnsignedShort();
                
            }
            else
            {
                length = Constants.FixedPayloadLength;
            }

            // we haven't received the actual payload yet
            if (input.ReadableBytes < length)
            {
                input.ResetReaderIndex();
                return;
            }

            byte[] payload = new byte[length];
            input.ReadBytes(payload);

            output.Add(
                new TorFrame
                {
                    CircuitId = circuitId,
                    Command = command,
                    Payload = payload
                }
            );
        }
    }
}
