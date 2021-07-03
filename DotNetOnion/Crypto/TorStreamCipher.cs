using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace DotNetOnion.Crypto
{
    public class TorStreamCipher : IDisposable
    {
        private const int KEY_SIZE = 16;
        private const int BLOCK_SIZE = 16;
        private readonly RijndaelManaged cipher;
        private readonly byte[] counter;
        private readonly byte[] counterOut;
        /* Next byte of keystream in counterOut */
        private int keystreamPointer = -1;
        private readonly byte[] key;
        private readonly object encryptLock = new();

        public TorStreamCipher(byte[] keyBytes) : this(keyBytes, null)
        {
        }

        public TorStreamCipher(byte[] keyBytes, byte[] iv)
        {
            key = keyBytes;
            cipher = createCipher(key);
            counter = new byte[BLOCK_SIZE];
            counterOut = new byte[BLOCK_SIZE];

            if (iv != null)
            {
                applyIV(iv);
            }
        }

        private void applyIV(byte[] iv)
        {
            if (iv.Length != BLOCK_SIZE)
            {
                throw new Exception("wrong IV length");
            }
            Buffer.BlockCopy(iv, 0, counter, 0, BLOCK_SIZE);
        }

        public byte[] Encrypt(byte[] data)
        {
            return Encrypt(data, 0, data.Length);
        }

        public byte[] Encrypt(byte[] data, int offset, int length)
        {
            lock (encryptLock)
            {
                byte[] result = new byte[length];

                for (int i = 0; i < length; i++)
                    result[i] = data[i + offset] ^= nextKeystreamByte();

                return result;
            }
        }

        private static RijndaelManaged createCipher(byte[] key)
        {
            return
                new RijndaelManaged()
                {
                    Key = key,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                };
        }

        private byte nextKeystreamByte()
        {
            if (keystreamPointer == -1 || (keystreamPointer >= BLOCK_SIZE))
                updateCounter();
            return counterOut[keystreamPointer++];
        }

        private void updateCounter()
        {
            encryptCounter();
            incrementCounter();
            keystreamPointer = 0;
        }

        private void encryptCounter()
        {
            var encrypted = cipher.CreateEncryptor().TransformFinalBlock(counter, 0, BLOCK_SIZE);
            Buffer.BlockCopy(encrypted, 0, counterOut, 0, BLOCK_SIZE);
        }

        private void incrementCounter()
        {
            int carry = 1;
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                int x = (counter[i] & 0xff) + carry;
                if (x > 0xff)
                    carry = 1;
                else
                    carry = 0;
                counter[i] = (byte)x;
            }
        }

        public void Dispose()
        {
            if (cipher != null)
                ((IDisposable)cipher).Dispose();
        }
    }
}
