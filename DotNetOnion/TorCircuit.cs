using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DotNetOnion.Cells;
using DotNetOnion.Crypto;
using DotNetOnion.Crypto.KDF;
using DotNetOnion.Helpers;
using DotNetOnion.KeyAgreements;
using static DotNetOnion.TorGuard;

namespace DotNetOnion
{
    public class TorCircuit
    {

        /*
         *  Existing Tor implementations choose their CircID values at random from
         *  among the available unused values.  To avoid distinguishability, new
         *  implementations should do the same. Implementations MAY give up and stop
         *  attempting to build new circuits on a channel, if a certain number of
         *  randomly chosen CircID values are all in use (today's Tor stops after 64).
         */
        private const int MaxCircuitIdGenerationRetry = 64;

        // The guard node that this circuit should be built on
        private readonly TorGuard guard;

        //TODO: make this a list of states, one for every hop in the circuit 
        private TorCryptoState guardCryptoState { get; set; }

        //TODO: circuitIds are not necesserily 2-byte integers (can be 4 on +4 protocol versions)
        private readonly ushort id;

        private TorCircuit(TorGuard guard, ushort id, TorCryptoState guardCryptoState)
        {
            this.guard = guard;
            this.id = id;
            this.guardCryptoState = guardCryptoState;
            //FIXME: HACK
            guard.CircuitDataHandlers.AddOrUpdate(id, Guard_NewMessageReceived, (_,_) => Guard_NewMessageReceived);
        }

        //TODO: Add parameter for hops
        public static async Task<TorCircuit> Create(TorGuard guard, bool isFast = false)
        {
            TaskCompletionSource<TorKdfResult> creationCompleted = new();

            IKeyAgreement keyAgreement = isFast switch
            {
                true => new FastKeyAgreement(),
                false => throw new NotImplementedException()
            };

            Cell cell = isFast switch
            {
                true =>
                    new CellCreateFast
                    {
                        X = keyAgreement.CreateClientMaterial()
                    },
                false =>
                    throw new NotImplementedException()
            };

            CircuitDataReceived preCreateHandler = (cell) => {
                var result = cell switch
                {
                    CellCreatedFast createdFast =>
                        keyAgreement.CalculateKey(createdFast.Y),
                    _ => throw new NotImplementedException()
                };
                creationCompleted.SetResult(result);
            };

            var id =
                RegisterCircuitId(guard, preCreateHandler);

            await guard.Send(id, cell);

            var kdfResult = await creationCompleted.Task;

            guard.CircuitDataHandlers.TryUpdate(id, preCreateHandler, null);

            return new TorCircuit(guard, id, TorCryptoState.CreateFromKdfResult(kdfResult));
        }

        private void Guard_NewMessageReceived(Cell cell)
        {

        }

        //FIXME: this is stupid, 3 memStream for this?!
        public async Task SendRelayCell(CellRelay cellRelay)
        {
            using (MemoryStream memStreamForDigestCalculation = new(Constants.FixedPayloadLength))
            using (BinaryWriter writer = new(memStreamForDigestCalculation))
            {
                cellRelay.SerializeForDigest(writer);
                guardCryptoState.forwardDigest.Update(memStreamForDigestCalculation.ToArray());
            }

            var digest = guardCryptoState.forwardDigest.GetDigestBytes();
            cellRelay.Digest = digest.Take(4).ToArray();

            byte[] encryptedCell;
            using (MemoryStream memStreamForEncryption = new(Constants.FixedPayloadLength))
            using (BinaryWriter writer = new(memStreamForEncryption))
            {
                cellRelay.Serialize(writer);
                encryptedCell = guardCryptoState.forwardCipher.Encrypt(memStreamForEncryption.ToArray());
            }

            await guard.Send(new TorFrame
            {
                CircuitId = id,
                Command = cellRelay.Command,
                Payload = encryptedCell
            });
        }

        private static ushort RegisterCircuitId(TorGuard guard, CircuitDataReceived preCreateHandler)
        {
            RandomNumberGenerator rngSource = RandomNumberGenerator.Create();

            for (var i = 0; i < MaxCircuitIdGenerationRetry; i++)
            {
                var randomBytes = new byte[2];
                rngSource.GetBytes(randomBytes);
                var tempId = randomBytes.ToUInt16BigEndian();

                if (tempId == 0)
                    continue;

                if (guard.CircuitDataHandlers.TryAdd(tempId, preCreateHandler))
                    return tempId;
            }

            throw new Exception("All circuitIds are taken, giving up.");
        }
    }
}
