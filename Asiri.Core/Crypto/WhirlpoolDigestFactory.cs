using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Provides the BouncyCastle Whirlpool digest implementation, used as the PBKDF2 PRF when a
    /// container was created with <see cref="HashAlgorithm.Whirlpool"/>. Kept in its own file,
    /// isolated from other hash algorithms, alongside the other Crypto.*DigestFactory/Xts*Cipher
    /// classes.
    /// </summary>
    internal static class WhirlpoolDigestFactory
    {
        public static IDigest Create()
        {
            return new WhirlpoolDigest();
        }
    }
}
