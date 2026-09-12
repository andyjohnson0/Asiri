using System;
using System.Security.Cryptography;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// A from-scratch PBKDF2 implementation (RFC 8018 section 5.2) built on .NET's own
    /// <see cref="HMACSHA256"/>/<see cref="HMACSHA512"/>, used in place of BouncyCastle's PBKDF2 for
    /// the two hash algorithms .NET has always had native HMAC support for. Measured roughly 1.7x
    /// (SHA-512) to 4.5x (SHA-256) faster than BouncyCastle's managed implementation for a
    /// 500,000-iteration derivation, on account of .NET's HMAC classes being backed by the OS's own
    /// crypto provider rather than a pure-managed one. BouncyCastle remains in use for Whirlpool and
    /// BLAKE2s-256 - see <see cref="Pbkdf2KeyDerivation"/> - since .NET has no built-in support for
    /// either. Deliberately avoids the newer <c>Rfc2898DeriveBytes.Pbkdf2</c> static helper and the
    /// <c>HashAlgorithmName</c>-based constructor, both of which require netstandard2.1/.NET 5+;
    /// Asiri.Core targets netstandard2.0.
    /// </summary>
    internal static class NativePbkdf2
    {
        /// <summary>
        /// Derives a key of the given length using PBKDF2 with <paramref name="prf"/> as the
        /// underlying HMAC. The caller owns <paramref name="prf"/> and is responsible for disposing
        /// it; it must already be initialized with the password as its key.
        /// </summary>
        public static byte[] DeriveKey(HMAC prf, byte[] salt, int iterations, int keyLengthBytes)
        {
            var hLen = prf.HashSize / 8;
            var blockCount = (keyLengthBytes + hLen - 1) / hLen;
            var derived = new byte[blockCount * hLen];

            var saltAndBlockIndex = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltAndBlockIndex, 0, salt.Length);

            for (var blockIndex = 1; blockIndex <= blockCount; blockIndex++)
            {
                saltAndBlockIndex[salt.Length] = (byte)(blockIndex >> 24);
                saltAndBlockIndex[salt.Length + 1] = (byte)(blockIndex >> 16);
                saltAndBlockIndex[salt.Length + 2] = (byte)(blockIndex >> 8);
                saltAndBlockIndex[salt.Length + 3] = (byte)blockIndex;

                var u = prf.ComputeHash(saltAndBlockIndex);
                var block = (byte[])u.Clone();
                for (var iteration = 1; iteration < iterations; iteration++)
                {
                    u = prf.ComputeHash(u);
                    for (var i = 0; i < hLen; i++)
                    {
                        block[i] ^= u[i];
                    }
                }

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
