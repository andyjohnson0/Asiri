using System;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// Computes a single PBKDF2 output block (RFC 8018 section 5.2: <c>T_i = F(P, S, c, i)</c>),
    /// against whichever <see cref="IPbkdf2Prf"/> is supplied - so the same block computation serves
    /// every <see cref="HashAlgorithm"/> this library supports, native-HMAC-backed or
    /// BouncyCastle-backed alike.
    ///
    /// Block <c>i</c> depends only on <c>i</c>, the password (baked into <paramref name="prf"/> as
    /// its HMAC key), and the salt - never on how many blocks are ultimately needed. That is what
    /// makes a shorter derivation's output always a byte-for-byte prefix of a longer one's, and is
    /// the property both <see cref="Pbkdf2KeyDerivation.DeriveKey"/> (one-shot, for a known
    /// algorithm/hash pair) and <see cref="IncrementalPbkdf2Stream"/> (grow-as-needed, for the
    /// brute-force search in <see cref="HeaderParser.TrySearchHashAlgorithmAsync"/>) build on.
    /// </summary>
    internal static class Pbkdf2BlockEngine
    {
        public static byte[] ComputeBlock(IPbkdf2Prf prf, byte[] salt, int iterations, int blockIndex)
        {
            var hLen = prf.HashLengthBytes;

            var saltAndBlockIndex = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltAndBlockIndex, 0, salt.Length);
            saltAndBlockIndex[salt.Length] = (byte)(blockIndex >> 24);
            saltAndBlockIndex[salt.Length + 1] = (byte)(blockIndex >> 16);
            saltAndBlockIndex[salt.Length + 2] = (byte)(blockIndex >> 8);
            saltAndBlockIndex[salt.Length + 3] = (byte)blockIndex;

            // U_1 = PRF(P, S || INT(i)); T_i = U_1 XOR U_2 XOR ... XOR U_c.
            var u = prf.ComputeHmac(saltAndBlockIndex);
            var block = (byte[])u.Clone();
            for (var iteration = 1; iteration < iterations; iteration++)
            {
                u = prf.ComputeHmac(u);
                for (var i = 0; i < hLen; i++)
                {
                    block[i] ^= u[i];
                }
            }

            return block;
        }
    }
}
