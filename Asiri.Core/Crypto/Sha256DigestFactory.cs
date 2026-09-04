using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Provides the BouncyCastle SHA-256 digest implementation, used as the PBKDF2 PRF when a
    /// container was created with <see cref="HashAlgorithm.Sha256"/>. Kept in its own file, isolated
    /// from other hash algorithms, alongside the other Crypto.*DigestFactory/Xts*Cipher classes.
    /// </summary>
    internal static class Sha256DigestFactory
    {
        public static IDigest Create()
        {
            return new Sha256Digest();
        }
    }
}
