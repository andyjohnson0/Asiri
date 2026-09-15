using System;
using Org.BouncyCastle.Crypto;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Encrypts or decrypts data in XTS mode (IEEE P1619), given already-initialized data and tweak
    /// block ciphers. BouncyCastle.Cryptography does not include an XTS mode implementation, so the
    /// tweak generation and GF(2^128) chaining defined by the XTS specification are implemented here,
    /// once - the chaining itself is identical regardless of which underlying block cipher XTS is
    /// applied to, and identical for encryption and decryption (only the block cipher's own
    /// direction, chosen by how the caller initialized <c>dataCipher</c>, differs) - so it is shared
    /// rather than duplicated across the Xts*Cipher classes. Those classes are responsible only for
    /// selecting and initializing the underlying cipher (see <see cref="XtsAesCipher"/>,
    /// <see cref="XtsSerpentCipher"/>).
    /// </summary>
    internal static class XtsBlockCipher
    {
        /// <summary>
        /// Decrypts a single data unit that is a whole number of blocks in length.
        /// </summary>
        /// <param name="dataCipher">The block cipher, initialized for decryption with the data key.</param>
        /// <param name="tweakCipher">The block cipher, initialized for encryption with the tweak key.</param>
        /// <param name="cipherText">The ciphertext to decrypt.</param>
        /// <param name="dataUnitNumber">The sequence number of the data unit.</param>
        public static byte[] Decrypt(IBlockCipher dataCipher, IBlockCipher tweakCipher, byte[] cipherText, long dataUnitNumber)
        {
            return ProcessDataUnit(dataCipher, tweakCipher, cipherText, dataUnitNumber);
        }

        /// <summary>
        /// Encrypts a single data unit that is a whole number of blocks in length. The XTS
        /// construction - C = E_K1(P xor T) xor T, and its decryption inverse - is symmetric in
        /// structure: this is the exact same xor/process-block/xor loop as <see cref="Decrypt"/>,
        /// differing only in that <paramref name="dataCipher"/> must be initialized for encryption
        /// (the tweak cipher is always initialized for encryption, regardless of data direction - the
        /// tweak itself is never "decrypted").
        /// </summary>
        /// <param name="dataCipher">The block cipher, initialized for encryption with the data key.</param>
        /// <param name="tweakCipher">The block cipher, initialized for encryption with the tweak key.</param>
        /// <param name="plainText">The plaintext to encrypt.</param>
        /// <param name="dataUnitNumber">The sequence number of the data unit.</param>
        public static byte[] Encrypt(IBlockCipher dataCipher, IBlockCipher tweakCipher, byte[] plainText, long dataUnitNumber)
        {
            return ProcessDataUnit(dataCipher, tweakCipher, plainText, dataUnitNumber);
        }

        private static byte[] ProcessDataUnit(IBlockCipher dataCipher, IBlockCipher tweakCipher, byte[] input, long dataUnitNumber)
        {
            var blockSize = dataCipher.GetBlockSize();
            if (input.Length % blockSize != 0)
            {
                throw new ArgumentException("Input length must be a multiple of the cipher's block size.", nameof(input));
            }

            var tweak = new byte[blockSize];
            var dataUnitBytes = BitConverter.GetBytes(dataUnitNumber);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(dataUnitBytes);
            }
            Buffer.BlockCopy(dataUnitBytes, 0, tweak, 0, dataUnitBytes.Length);

            var t = new byte[blockSize];
            tweakCipher.ProcessBlock(tweak, 0, t, 0);

            var blockCount = input.Length / blockSize;
            var output = new byte[input.Length];
            var block = new byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;
                for (var j = 0; j < blockSize; j++)
                {
                    block[j] = (byte)(input[offset + j] ^ t[j]);
                }

                dataCipher.ProcessBlock(block, 0, block, 0);

                for (var j = 0; j < blockSize; j++)
                {
                    output[offset + j] = (byte)(block[j] ^ t[j]);
                }

                MultiplyTweakByAlpha(t);
            }

            return output;
        }

        /// <summary>
        /// Multiplies the tweak block in place by the primitive element (alpha = 2) in GF(2^128),
        /// using the XTS reduction polynomial x^128 + x^7 + x^2 + x + 1. Correct for any 128-bit
        /// block cipher; VeraCrypt's supported XTS ciphers (AES, Serpent, Twofish) all use 128-bit
        /// blocks, per this project's own scope.
        /// </summary>
        private static void MultiplyTweakByAlpha(byte[] t)
        {
            var carry = 0;
            for (var i = 0; i < t.Length; i++)
            {
                var nextCarry = (t[i] >> 7) & 1;
                t[i] = (byte)((t[i] << 1) | carry);
                carry = nextCarry;
            }
            if (carry != 0)
            {
                t[0] ^= 0x87;
            }
        }
    }
}
