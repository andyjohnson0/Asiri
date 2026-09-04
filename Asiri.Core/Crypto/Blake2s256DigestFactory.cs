using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Provides the BouncyCastle BLAKE2s-256 digest implementation, used as the PBKDF2 PRF when a
    /// container was created with <see cref="HashAlgorithm.Blake2s256"/>. Kept in its own file,
    /// isolated from other hash algorithms, alongside the other Crypto.*DigestFactory/Xts*Cipher
    /// classes.
    /// </summary>
    internal static class Blake2s256DigestFactory
    {
        private const int DigestBits = 256;

        public static IDigest Create()
        {
            return new Blake2sDigest(DigestBits);
        }
    }
}
