using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DotNetOnion.Cells;
using DotNetOnion.Helpers;
using static DotNetOnion.TorCircuit;

namespace DotNetOnion
{
    public class TorStream
    {
        private readonly TorCircuit circuit;
        private readonly ushort id;

        private TorStream(TorCircuit circuit, ushort id)
        {
            this.circuit = circuit;
            this.id = id;
        }

        public static async Task<TorStream> StartDirectoryStream(TorCircuit circuit)
        {
            /*
            TaskCompletionSource<bool> creationCompleted = new();
            
            void preCreateHandler(Cell cell)
            {
                var result = cell switch
                {
                    CellRelayPlain createdFast =>
                        keyAgreement.CalculateKey(createdFast.Y),
                    _ => throw new NotImplementedException()
                };
                creationCompleted.SetResult(result);
            }*/

            /*var id =
                RegisterStreamId(circuit, null);

            await circuit.SendRelayCell(cell);

            var kdfResult = await creationCompleted.Task;

            guard.CircuitDataHandlers.TryUpdate(id, preCreateHandler, null);
            */
            //return new TorStream(circuit, id);

            return null;
        }



        private static ushort RegisterStreamId(TorCircuit circuit, StreamDataReceived preCreateHandler)
        {
            RandomNumberGenerator rngSource = RandomNumberGenerator.Create();

            while (true)
            {
                var randomBytes = new byte[2];
                rngSource.GetBytes(randomBytes);
                var tempId = SerializationHelper.ToUInt16BigEndian(randomBytes);

                if (tempId == 0)
                    continue;

                if (circuit.StreamDataHandlers.TryAdd(tempId, preCreateHandler))
                    return tempId;
            }

            throw new Exception("All circuitIds are taken, giving up.");
        }
    }
}
