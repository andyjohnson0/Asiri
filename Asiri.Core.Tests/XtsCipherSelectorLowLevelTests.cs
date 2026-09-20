using System;
using System.Collections.Generic;
using System.Reflection;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Validates the internal XtsCipherSelector dispatch directly, independent of any VeraCrypt
    /// container: confirms CryptoAlgorithm.Aes routes to the same result as calling the internal
    /// XtsAesCipher directly (already validated against a published IEEE 1619 test vector by
    /// XtsAesCipherLowLevelTests - not repeated here, since that's a property of XtsAesCipher, not of
    /// the dispatch), and that an unsupported CryptoAlgorithm value throws ArgumentException. Both
    /// types are accessed via reflection so the library project does not need to expose either or
    /// grant InternalsVisibleTo.
    ///
    /// EncryptThenDecrypt_RoundTripsForEveryAlgorithm below is deliberately not the only Encrypt
    /// coverage: a round trip only proves Encrypt and Decrypt agree with *each other*, which a bug
    /// present identically in both could still satisfy. XtsAesCipherLowLevelTests' published-vector
    /// test is what actually proves Encrypt correct for a single cipher; this class's round trip
    /// extends that confidence to the cascades, which have no equivalent published vector, by
    /// checking that Encrypt correctly inverts Decrypt - and Decrypt's own cascade ordering is
    /// already independently proven via CascadeDefinitionsLowLevelTests and the real-container
    /// Integration tests, so "correctly inverts a trusted Decrypt" is meaningfully strong evidence,
    /// not mere self-consistency.
    /// </summary>
    public class XtsCipherSelectorLowLevelTests
    {
        [Fact]
        public void Decrypt_Aes_MatchesXtsAesCipherDirectly()
        {
            var rnd = new Random(4242);
            var cipherText = RandomBytes(rnd, 512);
            var dataKey = RandomBytes(rnd, 32);
            var tweakKey = RandomBytes(rnd, 32);
            const long dataUnitNumber = 12345L;

            var viaSelector = InvokeSelector("Decrypt", CryptoAlgorithm.Aes, cipherText, dataKey, tweakKey, dataUnitNumber);
            var viaDirect = InvokeXtsAesCipher("Decrypt", cipherText, dataKey, tweakKey, dataUnitNumber);

            Assert.Equal(viaDirect, viaSelector);
        }

        [Fact]
        public void Encrypt_Aes_MatchesXtsAesCipherDirectly()
        {
            var rnd = new Random(4343);
            var plainText = RandomBytes(rnd, 512);
            var dataKey = RandomBytes(rnd, 32);
            var tweakKey = RandomBytes(rnd, 32);
            const long dataUnitNumber = 54321L;

            var viaSelector = InvokeSelector("Encrypt", CryptoAlgorithm.Aes, plainText, dataKey, tweakKey, dataUnitNumber);
            var viaDirect = InvokeXtsAesCipher("Encrypt", plainText, dataKey, tweakKey, dataUnitNumber);

            Assert.Equal(viaDirect, viaSelector);
        }

        [Fact]
        public void Decrypt_UnsupportedAlgorithm_ThrowsArgumentException()
        {
            var rnd = new Random(1);
            var cipherText = RandomBytes(rnd, 512);
            var dataKey = RandomBytes(rnd, 32);
            var tweakKey = RandomBytes(rnd, 32);

            Assert.Throws<ArgumentException>(() => InvokeSelector("Decrypt", (CryptoAlgorithm)99, cipherText, dataKey, tweakKey, dataUnitNumber: 0));
        }

        [Fact]
        public void Encrypt_UnsupportedAlgorithm_ThrowsArgumentException()
        {
            var rnd = new Random(2);
            var plainText = RandomBytes(rnd, 512);
            var dataKey = RandomBytes(rnd, 32);
            var tweakKey = RandomBytes(rnd, 32);

            Assert.Throws<ArgumentException>(() => InvokeSelector("Encrypt", (CryptoAlgorithm)99, plainText, dataKey, tweakKey, dataUnitNumber: 0));
        }

        public static IEnumerable<object[]> AllAlgorithms()
        {
            foreach (CryptoAlgorithm algorithm in Enum.GetValues(typeof(CryptoAlgorithm)))
            {
                yield return new object[] { algorithm };
            }
        }

        [Theory]
        [MemberData(nameof(AllAlgorithms))]
        public void EncryptThenDecrypt_RoundTripsForEveryAlgorithm(CryptoAlgorithm algorithm)
        {
            var componentCount = (int)InvokeCascadeDefinitions("GetComponentCount", algorithm);
            var keyLength = 32 * componentCount;

            var rnd = new Random(algorithm.GetHashCode() + 1000);
            var plainText = RandomBytes(rnd, 512);
            var dataKey = RandomBytes(rnd, keyLength);
            var tweakKey = RandomBytes(rnd, keyLength);
            const long dataUnitNumber = 999L;

            var cipherText = InvokeSelector("Encrypt", algorithm, plainText, dataKey, tweakKey, dataUnitNumber);
            Assert.NotEqual(plainText, cipherText);

            var roundTripped = InvokeSelector("Decrypt", algorithm, cipherText, dataKey, tweakKey, dataUnitNumber);
            Assert.Equal(plainText, roundTripped);
        }

        private static byte[] RandomBytes(Random rnd, int count)
        {
            var b = new byte[count];
            rnd.NextBytes(b);
            return b;
        }

        private static object InvokeCascadeDefinitions(string methodName, CryptoAlgorithm algorithm)
        {
            var type = Array.Find(typeof(HeaderParser).Assembly.GetTypes(), t => t.Name == "CascadeDefinitions")
                       ?? throw new InvalidOperationException("CascadeDefinitions type not found.");
            var method = type.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException($"CascadeDefinitions.{methodName} method not found.");
            return method.Invoke(null, new object[] { algorithm })!;
        }

        private static byte[] InvokeSelector(string methodName, CryptoAlgorithm algorithm, byte[] input, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var type = Array.Find(typeof(HeaderParser).Assembly.GetTypes(), t => t.Name == "XtsCipherSelector")
                       ?? throw new InvalidOperationException("XtsCipherSelector type not found.");
            var method = type.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException($"XtsCipherSelector.{methodName} method not found.");
            try
            {
                return (byte[])method.Invoke(null, new object[] { algorithm, input, dataKey, tweakKey, dataUnitNumber })!;
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                throw ex.InnerException;
            }
        }

        private static byte[] InvokeXtsAesCipher(string methodName, byte[] input, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var type = Array.Find(typeof(HeaderParser).Assembly.GetTypes(), t => t.Name == "XtsAesCipher")
                       ?? throw new InvalidOperationException("XtsAesCipher type not found.");
            var method = type.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException($"XtsAesCipher.{methodName} method not found.");
            return (byte[])method.Invoke(null, new object[] { input, dataKey, tweakKey, dataUnitNumber })!;
        }
    }
}
