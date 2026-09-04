using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Decrypts data using Twofish in XTS mode (IEEE P1619), built on BouncyCastle's Twofish block
    /// cipher primitive. The XTS tweak generation and GF(2^128) chaining are cipher-agnostic and
    /// shared via <see cref="XtsBlockCipher"/>; this class is responsible only for selecting and
    /// initializing Twofish as the underlying cipher.
    /// </summary>
    internal static class XtsTwofishCipher
    {
        /// <summary>
        /// Decrypts a single data unit that is a whole number of Twofish blocks in length.
        /// </summary>
        /// <param name="cipherText">The ciphertext to decrypt.</param>
        /// <param name="dataKey">The 256-bit key used to decrypt the data blocks.</param>
        /// <param name="tweakKey">The 256-bit key used to encrypt the data unit tweak.</param>
        /// <param name="dataUnitNumber">The sequence number of the data unit.</param>
        public static byte[] Decrypt(byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var dataCipher = new TwofishEngine();
            dataCipher.Init(false, new KeyParameter(dataKey));

            var tweakCipher = new TwofishEngine();
            tweakCipher.Init(true, new KeyParameter(tweakKey));

            return XtsBlockCipher.Decrypt(dataCipher, tweakCipher, cipherText, dataUnitNumber);
        }
    }
}
