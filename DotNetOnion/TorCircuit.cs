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
using NOnion.Cells;

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
            guard.CircuitDataHandlers[id] = Guard_NewMessageReceived;
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

            ICell cell = isFast switch
            {
                true =>
                    new CellCreateFast(keyAgreement.CreateClientMaterial()),
                false =>
                    throw new NotImplementedException()
            };

            void preCreateHandler(ICell cell)
            {
                var result = cell switch
                {
                    CellCreatedFast createdFast =>
                        keyAgreement.CalculateKey(createdFast.Y),
                    _ => throw new NotImplementedException()
                };
                creationCompleted.SetResult(result);
            }

            var id =
                RegisterCircuitId(guard, preCreateHandler);

            await guard.Send(id, cell);

            var kdfResult = await creationCompleted.Task;

            guard.CircuitDataHandlers.TryUpdate(id, preCreateHandler, null);

            return new TorCircuit(guard, id, TorCryptoState.CreateFromKdfResult(kdfResult));
        }

        private void Guard_NewMessageReceived(ICell cell)
        {
            switch (cell)
            {
                case CellRelayEncrypted encryptedRelayCell:
                    HandleEncryptedRelayCell(encryptedRelayCell);
                    break;
            }
        }

        private void HandleEncryptedRelayCell(CellRelayEncrypted encryptedRelayCell)
        {
            var decryptedRelayCellBytes =
                guardCryptoState.backwardCipher.Encrypt(encryptedRelayCell.EncryptedData);
            var recognized = BitConverter.ToUInt16(decryptedRelayCellBytes, 1);
            if (recognized != 0) throw new Exception("wat?!");
            var digest = decryptedRelayCellBytes.Skip(5).Take(4).ToArray();

            Array.Clear(decryptedRelayCellBytes, 5, 4);
            var computedDigest =
                guardCryptoState.backwardDigest.PeekDigest(decryptedRelayCellBytes, 0, decryptedRelayCellBytes.Length).Take(4);

            if (!digest.SequenceEqual(computedDigest))
                throw new Exception("wat?");

            guardCryptoState.backwardDigest.Update(decryptedRelayCellBytes, 0, decryptedRelayCellBytes.Length);

            CellRelayPlain decryptedRelayCell = new();
            decryptedRelayCell.FromBytes(decryptedRelayCellBytes);
        }

        private void HandleDecryptedRelayCell(CellRelayPlain plainRelayCell)
        {

        }

        public async Task SendRelayCell(CellRelayPlain plainRelayCell)
        {
            guardCryptoState.forwardDigest.Update(plainRelayCell.ToBytes(true));
            var digest =
                guardCryptoState.forwardDigest.GetDigestBytes();

            plainRelayCell.Digest = new byte[4];
            Buffer.BlockCopy(digest, 0, plainRelayCell.Digest, 0, 4);

            await guard.Send(id,
                new CellRelayEncrypted()
                {
                    EncryptedData = guardCryptoState.forwardCipher.Encrypt(plainRelayCell.ToBytes(false))
                });
        }

        private static ushort RegisterCircuitId(TorGuard guard, Action<ICell> preCreateHandler)
        {
            RandomNumberGenerator rngSource = RandomNumberGenerator.Create();

            for (var i = 0; i < MaxCircuitIdGenerationRetry; i++)
            {
                var randomBytes = new byte[2];
                rngSource.GetBytes(randomBytes);
                var tempId = SerializationHelper.ToUInt16BigEndian(randomBytes);

                if (tempId == 0)
                    continue;

                if (guard.CircuitDataHandlers.TryAdd(tempId, preCreateHandler))
                    return tempId;
            }

            throw new Exception("All circuitIds are taken, giving up.");
        }
    }
}
