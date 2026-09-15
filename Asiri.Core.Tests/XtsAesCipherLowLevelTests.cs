using System;
using System.Reflection;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Validates the internal AES-XTS-256 implementation directly against a published IEEE 1619
    /// (also distributed as an OpenSSL EVP test vector, evpciph_aes_common.txt) test vector,
    /// independent of any VeraCrypt container. This pins down key ordering (the first 32 bytes of
    /// the derived key material is the data key, the next 32 bytes is the tweak key), tweak
    /// generation (AES-encrypt the data-unit sequence number with the tweak key), and GF(2^128)
    /// tweak doubling using the 0x87 reduction polynomial - exactly what HeaderParser relies on to
    /// decrypt the volume header. Accesses the internal XtsAesCipher type via reflection so the
    /// library project does not need to expose it or grant InternalsVisibleTo.
    /// </summary>
    public class XtsAesCipherLowLevelTests
    {
        // Key = Key1 (32 bytes, data key) || Key2 (32 bytes, tweak key).
        private const string KeyHex =
            "27182818284590452353602874713526624977572470936999595749669676273141592653589793238462643383279502884197169399375105820974944592";

        // IV = 0xff followed by 15 zero bytes, i.e. data-unit sequence number 255 (little-endian).
        private const long DataUnitNumber = 255L;

        private const string PlaintextHex =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

        private const string CiphertextHex =
            "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed43851ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151";

        [Fact]
        public void Decrypt_PublishedIeee1619XtsAes256Vector_ProducesExpectedPlaintext()
        {
            var key = Convert.FromHexString(KeyHex);
            var key1 = key[..32];
            var key2 = key[32..];
            var ciphertext = Convert.FromHexString(CiphertextHex);
            var expectedPlaintext = Convert.FromHexString(PlaintextHex);

            var actualPlaintext = InvokeDecrypt(ciphertext, key1, key2, DataUnitNumber);

            Assert.Equal(expectedPlaintext, actualPlaintext);
        }

        [Fact]
        public void Encrypt_PublishedIeee1619XtsAes256Vector_ProducesExpectedCiphertext()
        {
            // The independent-oracle counterpart to the Decrypt test above: encrypting the vector's
            // known plaintext must reproduce its known ciphertext exactly. This is what makes Encrypt
            // trustworthy beyond "it round-trips with our own Decrypt" - a bug that broke both
            // Encrypt and Decrypt identically (e.g. a wrong key half, or a wrong tweak direction)
            // could still round-trip with itself while never matching this externally-published
            // vector.
            var key = Convert.FromHexString(KeyHex);
            var key1 = key[..32];
            var key2 = key[32..];
            var plaintext = Convert.FromHexString(PlaintextHex);
            var expectedCiphertext = Convert.FromHexString(CiphertextHex);

            var actualCiphertext = InvokeEncrypt(plaintext, key1, key2, DataUnitNumber);

            Assert.Equal(expectedCiphertext, actualCiphertext);
        }

        [Fact]
        public void Decrypt_WithKey1AndKey2Swapped_DoesNotProduceExpectedPlaintext()
        {
            // If key ordering didn't matter to this implementation, the preceding test could pass
            // by coincidence. This confirms swapping the two key halves breaks decryption, so the
            // "correct order" test above is actually a meaningful check of key ordering.
            var key = Convert.FromHexString(KeyHex);
            var key1 = key[..32];
            var key2 = key[32..];
            var ciphertext = Convert.FromHexString(CiphertextHex);
            var expectedPlaintext = Convert.FromHexString(PlaintextHex);

            var actualPlaintext = InvokeDecrypt(ciphertext, key2, key1, DataUnitNumber);

            Assert.NotEqual(expectedPlaintext, actualPlaintext);
        }

        private static byte[] InvokeDecrypt(byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            return InvokeXtsAesCipher("Decrypt", cipherText, dataKey, tweakKey, dataUnitNumber);
        }

        private static byte[] InvokeEncrypt(byte[] plainText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            return InvokeXtsAesCipher("Encrypt", plainText, dataKey, tweakKey, dataUnitNumber);
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
