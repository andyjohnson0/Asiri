using System;
using System.Collections.Generic;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Maps every <see cref="CryptoAlgorithm"/> value - single ciphers and cascades alike - to the
    /// ordered sequence of single ciphers it decrypts as. For a single-cipher value this is a
    /// one-element sequence containing only itself. For a cascade, VeraCrypt's own source
    /// (Crypto.c's EncryptionAlgorithms table) applies the cascaded ciphers in a fixed order for
    /// encryption and the exact reverse order for decryption; the sequences below are already in
    /// decryption order, which is also the order the cascade's own name lists its ciphers in
    /// (e.g. "Serpent-Twofish-AES" decrypts Serpent, then Twofish, then AES).
    /// </summary>
    internal static class CascadeDefinitions
    {
        private static readonly Dictionary<CryptoAlgorithm, CryptoAlgorithm[]> DecryptOrder = new Dictionary<CryptoAlgorithm, CryptoAlgorithm[]>
        {
            [CryptoAlgorithm.Aes] = new[] { CryptoAlgorithm.Aes },
            [CryptoAlgorithm.Serpent] = new[] { CryptoAlgorithm.Serpent },
            [CryptoAlgorithm.Twofish] = new[] { CryptoAlgorithm.Twofish },
            [CryptoAlgorithm.Camellia] = new[] { CryptoAlgorithm.Camellia },

            [CryptoAlgorithm.AesTwofish] = new[] { CryptoAlgorithm.Aes, CryptoAlgorithm.Twofish },
            [CryptoAlgorithm.AesTwofishSerpent] = new[] { CryptoAlgorithm.Aes, CryptoAlgorithm.Twofish, CryptoAlgorithm.Serpent },
            [CryptoAlgorithm.SerpentAes] = new[] { CryptoAlgorithm.Serpent, CryptoAlgorithm.Aes },
            [CryptoAlgorithm.SerpentTwofishAes] = new[] { CryptoAlgorithm.Serpent, CryptoAlgorithm.Twofish, CryptoAlgorithm.Aes },
            [CryptoAlgorithm.TwofishSerpent] = new[] { CryptoAlgorithm.Twofish, CryptoAlgorithm.Serpent },
            [CryptoAlgorithm.CamelliaSerpent] = new[] { CryptoAlgorithm.Camellia, CryptoAlgorithm.Serpent },
        };

        /// <summary>
        /// The size, in bytes, of a single component cipher's data key (and, separately, its tweak
        /// key) within a VeraCrypt header's key material - 256 bits, regardless of which cipher.
        /// </summary>
        public const int ComponentKeySize = 32;

        /// <summary>
        /// The single ciphers that <paramref name="algorithm"/> decrypts as, in decryption order.
        /// For a single-cipher algorithm this is a one-element array containing only itself.
        /// </summary>
        public static CryptoAlgorithm[] GetDecryptOrder(CryptoAlgorithm algorithm)
        {
            if (!DecryptOrder.TryGetValue(algorithm, out var components))
            {
                throw new ArgumentException($"Unsupported encryption algorithm: {algorithm}.", nameof(algorithm));
            }
            return components;
        }

        /// <summary>
        /// The number of single ciphers <paramref name="algorithm"/> is composed of: 1 for a single
        /// cipher, 2 or 3 for a cascade.
        /// </summary>
        public static int GetComponentCount(CryptoAlgorithm algorithm)
        {
            return GetDecryptOrder(algorithm).Length;
        }

        /// <summary>
        /// True if <paramref name="algorithm"/> is a value this library knows how to decrypt with -
        /// every single cipher and every supported cascade.
        /// </summary>
        public static bool IsSupported(CryptoAlgorithm algorithm)
        {
            return DecryptOrder.ContainsKey(algorithm);
        }
    }
}
