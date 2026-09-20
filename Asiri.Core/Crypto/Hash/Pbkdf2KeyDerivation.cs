using System;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// Derives keys from a password and salt using PBKDF2, with the underlying PRF selected per
    /// <see cref="HashAlgorithm"/> by <see cref="Pbkdf2PrfFactory"/>. VeraCrypt allows the hash
    /// algorithm to be selected independently of the encryption algorithm, so this is kept separate
    /// from the cipher code under Crypto.&lt;CipherName&gt;.
    /// </summary>
    internal static class Pbkdf2KeyDerivation
    {
        /// <summary>
        /// Derives a key of the given length from a password and salt, using PBKDF2 with the given
        /// hash algorithm and iteration count. A one-shot equivalent of computing every block up
        /// front via <see cref="Pbkdf2BlockEngine"/> - used by the explicit-parameters open path
        /// (<see cref="HeaderParser.ParseAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, int, IEnumerable{FileInfo}, CancellationToken)"/>),
        /// where the caller already knows exactly how much key material is needed. The brute-force
        /// search path uses <see cref="IncrementalPbkdf2Stream"/> instead, since it doesn't know
        /// that in advance.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm to use as the PBKDF2 PRF.</param>
        /// <param name="passwordBytes">The UTF-8 encoded password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The PBKDF2 iteration count.</param>
        /// <param name="keyLengthBits">The length of the derived key, in bits.</param>
        public static byte[] DeriveKey(HashAlgorithm hashAlgorithm, byte[] passwordBytes, byte[] salt, int iterations, int keyLengthBits)
        {
            var keyLengthBytes = keyLengthBits / 8;

            using (var prf = Pbkdf2PrfFactory.Create(hashAlgorithm, passwordBytes))
            {
                var hLen = prf.HashLengthBytes;
                var blockCount = (keyLengthBytes + hLen - 1) / hLen;
                var derived = new byte[blockCount * hLen];

                for (var blockIndex = 1; blockIndex <= blockCount; blockIndex++)
                {
                    var block = Pbkdf2BlockEngine.ComputeBlock(prf, salt, iterations, blockIndex);
                    Buffer.BlockCopy(block, 0, derived, (blockIndex - 1) * hLen, hLen);
                }

                if (derived.Length == keyLengthBytes)
                {
                    return derived;
                }

                var result = new byte[keyLengthBytes];
                Buffer.BlockCopy(derived, 0, result, 0, keyLengthBytes);
                return result;
            }
        }
    }
}
