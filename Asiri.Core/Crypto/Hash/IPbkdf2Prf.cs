using System;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// An HMAC, already initialized with a key, usable as PBKDF2's underlying PRF (RFC 8018 section
    /// 5.2). Exists so <see cref="Pbkdf2BlockEngine"/> can drive the PBKDF2 block/iteration loop
    /// once, against either .NET's own HMAC classes (<see cref="NativeHmacPrf"/>, for SHA-512 and
    /// SHA-256) or BouncyCastle's (<see cref="BouncyCastleHmacPrf"/>, for Whirlpool and
    /// BLAKE2s-256, which .NET has no built-in support for) - see <see cref="Pbkdf2PrfFactory"/> for
    /// which is chosen per <see cref="HashAlgorithm"/>.
    /// </summary>
    internal interface IPbkdf2Prf : IDisposable
    {
        /// <summary>The PRF's output length, in bytes (e.g. 64 for SHA-512, 32 for SHA-256).</summary>
        int HashLengthBytes { get; }

        /// <summary>Computes HMAC(key, message) using the key this instance was created with.</summary>
        byte[] ComputeHmac(byte[] message);
    }
}
