using System;
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

            var viaSelector = InvokeSelectorDecrypt(CryptoAlgorithm.Aes, cipherText, dataKey, tweakKey, dataUnitNumber);
            var viaDirect = InvokeXtsAesCipherDecrypt(cipherText, dataKey, tweakKey, dataUnitNumber);

            Assert.Equal(viaDirect, viaSelector);
        }

        [Fact]
        public void Decrypt_UnsupportedAlgorithm_ThrowsArgumentException()
        {
            var rnd = new Random(1);
            var cipherText = RandomBytes(rnd, 512);
            var dataKey = RandomBytes(rnd, 32);
            var tweakKey = RandomBytes(rnd, 32);

            Assert.Throws<ArgumentException>(() => InvokeSelectorDecrypt((CryptoAlgorithm)99, cipherText, dataKey, tweakKey, dataUnitNumber: 0));
        }

        private static byte[] RandomBytes(Random rnd, int count)
        {
            var b = new byte[count];
            rnd.NextBytes(b);
            return b;
        }

        private static byte[] InvokeSelectorDecrypt(CryptoAlgorithm algorithm, byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var type = Array.Find(typeof(HeaderParser).Assembly.GetTypes(), t => t.Name == "XtsCipherSelector")
                       ?? throw new InvalidOperationException("XtsCipherSelector type not found.");
            var method = type.GetMethod("Decrypt", BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException("XtsCipherSelector.Decrypt method not found.");
            try
            {
                return (byte[])method.Invoke(null, new object[] { algorithm, cipherText, dataKey, tweakKey, dataUnitNumber })!;
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                throw ex.InnerException;
            }
        }

        private static byte[] InvokeXtsAesCipherDecrypt(byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var type = Array.Find(typeof(HeaderParser).Assembly.GetTypes(), t => t.Name == "XtsAesCipher")
                       ?? throw new InvalidOperationException("XtsAesCipher type not found.");
            var method = type.GetMethod("Decrypt", BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException("XtsAesCipher.Decrypt method not found.");
            return (byte[])method.Invoke(null, new object[] { cipherText, dataKey, tweakKey, dataUnitNumber })!;
        }
    }
}
