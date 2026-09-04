using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// Derives keys from a password and salt using PBKDF2, with the underlying hash algorithm
    /// selected per <see cref="HashAlgorithm"/> via <see cref="HashDigestSelector"/>. VeraCrypt
    /// allows the hash algorithm to be selected independently of the encryption algorithm, so this
    /// is kept separate from the cipher code under Crypto.&lt;CipherName&gt;.
    /// </summary>
    internal static class Pbkdf2KeyDerivation
    {
        /// <summary>
        /// Derives a key of the given length from a password and salt, using PBKDF2 with the given
        /// hash algorithm and iteration count.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm to use as the PBKDF2 PRF.</param>
        /// <param name="passwordBytes">The UTF-8 encoded password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The PBKDF2 iteration count.</param>
        /// <param name="keyLengthBits">The length of the derived key, in bits.</param>
        public static byte[] DeriveKey(HashAlgorithm hashAlgorithm, byte[] passwordBytes, byte[] salt, int iterations, int keyLengthBits)
        {
            var generator = new Pkcs5S2ParametersGenerator(HashDigestSelector.Create(hashAlgorithm));
            generator.Init(passwordBytes, salt, iterations);
            var keyParam = (KeyParameter)generator.GenerateDerivedParameters("AES", keyLengthBits);
            return keyParam.GetKey();
        }
    }
}
