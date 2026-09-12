using System.Security.Cryptography;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// Selects and initializes the <see cref="IPbkdf2Prf"/> to use as PBKDF2's PRF for a given
    /// <see cref="HashAlgorithm"/>: .NET's own HMAC for SHA-512/SHA-256 (see
    /// <see cref="NativeHmacPrf"/>), BouncyCastle's for Whirlpool/BLAKE2s-256 (see
    /// <see cref="BouncyCastleHmacPrf"/>).
    /// </summary>
    internal static class Pbkdf2PrfFactory
    {
        /// <summary>Creates a PRF already initialized with <paramref name="key"/>. Caller disposes.</summary>
        public static IPbkdf2Prf Create(HashAlgorithm hashAlgorithm, byte[] key)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.Sha512:
                    return new NativeHmacPrf(new HMACSHA512(key));
                case HashAlgorithm.Sha256:
                    return new NativeHmacPrf(new HMACSHA256(key));
                default:
                    // HashDigestSelector.Create throws ArgumentException for anything it doesn't
                    // recognise, which is exactly the validation this factory needs for an
                    // unsupported HashAlgorithm too - no need to duplicate it here.
                    var digest = HashDigestSelector.Create(hashAlgorithm);
                    return new BouncyCastleHmacPrf(digest, key);
            }
        }
    }
}
