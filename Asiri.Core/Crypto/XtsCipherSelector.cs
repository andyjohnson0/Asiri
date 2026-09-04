using System;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Decrypts a single XTS data unit, selecting the underlying cipher per <see cref="CryptoAlgorithm"/>.
    /// Kept in its own file, isolated from other ciphers, alongside the other
    /// Crypto.*DigestFactory/Xts*Cipher classes, mirroring Crypto.Hash's role for <see cref="HashAlgorithm"/>.
    /// </summary>
    internal static class XtsCipherSelector
    {
        /// <summary>
        /// Decrypts a single data unit using the cipher identified by <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm">The encryption algorithm to decrypt with.</param>
        /// <param name="cipherText">The ciphertext to decrypt.</param>
        /// <param name="dataKey">The key used to decrypt the data blocks.</param>
        /// <param name="tweakKey">The key used to encrypt the data unit tweak.</param>
        /// <param name="dataUnitNumber">The sequence number of the data unit.</param>
        public static byte[] Decrypt(CryptoAlgorithm algorithm, byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            switch (algorithm)
            {
                case CryptoAlgorithm.Aes:
                    return XtsAesCipher.Decrypt(cipherText, dataKey, tweakKey, dataUnitNumber);
                case CryptoAlgorithm.Serpent:
                    return XtsSerpentCipher.Decrypt(cipherText, dataKey, tweakKey, dataUnitNumber);
                case CryptoAlgorithm.Twofish:
                    return XtsTwofishCipher.Decrypt(cipherText, dataKey, tweakKey, dataUnitNumber);
                case CryptoAlgorithm.Camellia:
                    return XtsCamelliaCipher.Decrypt(cipherText, dataKey, tweakKey, dataUnitNumber);
                default:
                    throw new ArgumentException($"Unsupported encryption algorithm: {algorithm}.", nameof(algorithm));
            }
        }
    }
}
