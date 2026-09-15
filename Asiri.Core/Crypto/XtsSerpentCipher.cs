using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Decrypts data using Serpent in XTS mode (IEEE P1619), built on BouncyCastle's Serpent block
    /// cipher primitive. The XTS tweak generation and GF(2^128) chaining are cipher-agnostic and
    /// shared via <see cref="XtsBlockCipher"/>; this class is responsible only for selecting and
    /// initializing Serpent as the underlying cipher.
    /// </summary>
    internal static class XtsSerpentCipher
    {
        /// <summary>
        /// Decrypts a single data unit that is a whole number of Serpent blocks in length.
        /// </summary>
        /// <param name="cipherText">The ciphertext to decrypt.</param>
        /// <param name="dataKey">The 256-bit key used to decrypt the data blocks.</param>
        /// <param name="tweakKey">The 256-bit key used to encrypt the data unit tweak.</param>
        /// <param name="dataUnitNumber">The sequence number of the data unit.</param>
        public static byte[] Decrypt(byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var dataCipher = new SerpentEngine();
            dataCipher.Init(false, new KeyParameter(dataKey));

            var tweakCipher = new SerpentEngine();
            tweakCipher.Init(true, new KeyParameter(tweakKey));

            return XtsBlockCipher.Decrypt(dataCipher, tweakCipher, cipherText, dataUnitNumber);
        }

        /// <summary>
        /// Encrypts a single data unit that is a whole number of Serpent blocks in length.
        /// </summary>
        /// <param name="plainText">The plaintext to encrypt.</param>
        /// <param name="dataKey">The 256-bit key used to encrypt the data blocks.</param>
        /// <param name="tweakKey">The 256-bit key used to encrypt the data unit tweak.</param>
        /// <param name="dataUnitNumber">The sequence number of the data unit.</param>
        public static byte[] Encrypt(byte[] plainText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var dataCipher = new SerpentEngine();
            dataCipher.Init(true, new KeyParameter(dataKey));

            var tweakCipher = new SerpentEngine();
            tweakCipher.Init(true, new KeyParameter(tweakKey));

            return XtsBlockCipher.Encrypt(dataCipher, tweakCipher, plainText, dataUnitNumber);
        }
    }
}
