using System;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Decrypts a single XTS data unit, selecting the underlying cipher(s) per <see cref="CryptoAlgorithm"/>.
    /// A cascade is decrypted as a sequence of ordinary, independent single-cipher XTS decrypts -
    /// each cascaded cipher has its own 256-bit data key and 256-bit tweak key, sliced from the
    /// caller's key material per <see cref="CascadeDefinitions"/> - applied one after another in the
    /// cascade's decryption order. Kept in its own file, isolated from other ciphers, alongside the
    /// other Crypto.*DigestFactory/Xts*Cipher classes, mirroring Crypto.Hash's role for
    /// <see cref="HashAlgorithm"/>.
    /// </summary>
    internal static class XtsCipherSelector
    {
        /// <summary>
        /// Decrypts a single data unit using the cipher(s) identified by <paramref name="algorithm"/>.
        /// For a cascade, <paramref name="dataKey"/> and <paramref name="tweakKey"/> must each be
        /// <see cref="CascadeDefinitions.ComponentKeySize"/> * (number of component ciphers) bytes
        /// long, holding every component's key material concatenated in the cascade's key-segment
        /// order (see <see cref="CascadeDefinitions"/>).
        /// </summary>
        /// <param name="algorithm">The encryption algorithm to decrypt with.</param>
        /// <param name="cipherText">The ciphertext to decrypt.</param>
        /// <param name="dataKey">The key material used to decrypt the data blocks.</param>
        /// <param name="tweakKey">The key material used to encrypt the data unit tweak.</param>
        /// <param name="dataUnitNumber">
        /// The sequence number of the data unit. The same value is used, unchanged, for every
        /// cascaded cipher: the tweak is a property of the data unit's position, not of which cipher
        /// layer is being applied, matching VeraCrypt's own cascade implementation.
        /// </param>
        public static byte[] Decrypt(CryptoAlgorithm algorithm, byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var decryptOrder = CascadeDefinitions.GetDecryptOrder(algorithm);
            if (decryptOrder.Length == 1)
            {
                return DecryptSingle(decryptOrder[0], cipherText, dataKey, tweakKey, dataUnitNumber);
            }

            // Key material is laid out in key-segment order, which is the reverse of decryption
            // order (see CascadeDefinitions) - e.g. for Serpent-Twofish-AES (decrypt order Serpent,
            // Twofish, AES), the key segments are laid out AES, Twofish, Serpent.
            var componentSize = CascadeDefinitions.ComponentKeySize;
            var expectedKeyLength = componentSize * decryptOrder.Length;
            if (dataKey.Length != expectedKeyLength || tweakKey.Length != expectedKeyLength)
            {
                throw new ArgumentException(
                    $"Key material for {algorithm} cascade must be {expectedKeyLength} bytes; " +
                    $"got data key {dataKey.Length}, tweak key {tweakKey.Length}.");
            }

            var result = cipherText;
            for (var i = 0; i < decryptOrder.Length; i++)
            {
                var cipher = decryptOrder[i];
                var segmentIndex = decryptOrder.Length - 1 - i;
                var segmentOffset = segmentIndex * componentSize;

                var componentDataKey = new byte[componentSize];
                var componentTweakKey = new byte[componentSize];
                Buffer.BlockCopy(dataKey, segmentOffset, componentDataKey, 0, componentSize);
                Buffer.BlockCopy(tweakKey, segmentOffset, componentTweakKey, 0, componentSize);

                result = DecryptSingle(cipher, result, componentDataKey, componentTweakKey, dataUnitNumber);
            }
            return result;
        }

        private static byte[] DecryptSingle(CryptoAlgorithm cipher, byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            switch (cipher)
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
                    throw new ArgumentException($"Unsupported component cipher: {cipher}.", nameof(cipher));
            }
        }
    }
}
