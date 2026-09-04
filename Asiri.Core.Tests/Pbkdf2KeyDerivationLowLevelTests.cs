using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Validates the internal PBKDF2 key derivation directly, independent of any VeraCrypt
    /// container, by cross-checking against .NET's built-in Rfc2898DeriveBytes.Pbkdf2 - an
    /// implementation independent of the BouncyCastle-based code under test, exactly as
    /// SyntheticHeaderRoundTripTests and SyntheticContainerHelper already do for the AES-XTS and
    /// full header round trip. Accesses the internal Pbkdf2KeyDerivation type via reflection so the
    /// library project does not need to expose it or grant InternalsVisibleTo.
    /// </summary>
    public class Pbkdf2KeyDerivationLowLevelTests
    {
        [Fact]
        public void DeriveKey_Sha512_MatchesIndependentRfc2898Implementation()
        {
            var password = Encoding.UTF8.GetBytes("correct horse battery staple");
            var salt = Encoding.UTF8.GetBytes("some-salt-value-1234567890123456");
            const int iterations = 1000;
            const int keyLengthBits = 512;

            var actual = InvokeDeriveKey(HashAlgorithm.Sha512, password, salt, iterations, keyLengthBits);

            var expected = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, keyLengthBits / 8);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void DeriveKey_DifferentPasswords_ProduceDifferentKeys()
        {
            // Confirms the preceding cross-check is actually sensitive to the password, rather than
            // returning a fixed buffer that happens to match by coincidence.
            var salt = Encoding.UTF8.GetBytes("some-salt-value-1234567890123456");
            const int iterations = 1000;
            const int keyLengthBits = 512;

            var keyA = InvokeDeriveKey(HashAlgorithm.Sha512, Encoding.UTF8.GetBytes("password-a"), salt, iterations, keyLengthBits);
            var keyB = InvokeDeriveKey(HashAlgorithm.Sha512, Encoding.UTF8.GetBytes("password-b"), salt, iterations, keyLengthBits);

            Assert.NotEqual(keyA, keyB);
        }

        [Fact]
        public void DeriveKey_DifferentSalts_ProduceDifferentKeys()
        {
            var password = Encoding.UTF8.GetBytes("correct horse battery staple");
            const int iterations = 1000;
            const int keyLengthBits = 512;

            var keyA = InvokeDeriveKey(HashAlgorithm.Sha512, password, Encoding.UTF8.GetBytes("salt-a"), iterations, keyLengthBits);
            var keyB = InvokeDeriveKey(HashAlgorithm.Sha512, password, Encoding.UTF8.GetBytes("salt-b"), iterations, keyLengthBits);

            Assert.NotEqual(keyA, keyB);
        }

        [Fact]
        public void DeriveKey_ReturnsRequestedKeyLength()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");

            var key = InvokeDeriveKey(HashAlgorithm.Sha512, password, salt, iterations: 1, keyLengthBits: 512);

            Assert.Equal(64, key.Length);
        }

        [Fact]
        public void DeriveKey_UnsupportedHashAlgorithm_ThrowsArgumentException()
        {
            var password = Encoding.UTF8.GetBytes("password");
            var salt = Encoding.UTF8.GetBytes("salt");

            Assert.Throws<ArgumentException>(() =>
                InvokeDeriveKey((HashAlgorithm)99, password, salt, iterations: 1, keyLengthBits: 512));
        }

        private static byte[] InvokeDeriveKey(HashAlgorithm hashAlgorithm, byte[] passwordBytes, byte[] salt, int iterations, int keyLengthBits)
        {
            var type = Array.Find(typeof(HeaderParser).Assembly.GetTypes(), t => t.Name == "Pbkdf2KeyDerivation")
                       ?? throw new InvalidOperationException("Pbkdf2KeyDerivation type not found.");
            var method = type.GetMethod("DeriveKey", BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException("Pbkdf2KeyDerivation.DeriveKey method not found.");
            try
            {
                return (byte[])method.Invoke(null, new object[] { hashAlgorithm, passwordBytes, salt, iterations, keyLengthBits })!;
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                throw ex.InnerException;
            }
        }
    }
}
