using System;
using System.Collections.Generic;
using System.Reflection;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Validates the internal cascade decrypt-order table and the cascade decryption logic built on
    /// top of it, directly and independent of any VeraCrypt container. The exact orderings asserted
    /// here were derived from VeraCrypt's own source (Common/Crypto.c's EncryptionAlgorithms table
    /// and EAInit's key-consumption loop, and Common/Volumes.c's primary/secondary key-half split):
    /// a cascade decrypts in the same left-to-right order as its display name, while its key
    /// material is laid out in the reverse (encryption) order. Accesses the internal
    /// CascadeDefinitions and Xts*Cipher types via reflection so the library project does not need
    /// to expose them or grant InternalsVisibleTo.
    /// </summary>
    public class CascadeDefinitionsLowLevelTests
    {
        public static IEnumerable<object[]> DecryptOrderCases()
        {
            yield return new object[] { CryptoAlgorithm.Aes, new[] { CryptoAlgorithm.Aes } };
            yield return new object[] { CryptoAlgorithm.Serpent, new[] { CryptoAlgorithm.Serpent } };
            yield return new object[] { CryptoAlgorithm.Twofish, new[] { CryptoAlgorithm.Twofish } };
            yield return new object[] { CryptoAlgorithm.Camellia, new[] { CryptoAlgorithm.Camellia } };
            yield return new object[] { CryptoAlgorithm.AesTwofish, new[] { CryptoAlgorithm.Aes, CryptoAlgorithm.Twofish } };
            yield return new object[] { CryptoAlgorithm.AesTwofishSerpent, new[] { CryptoAlgorithm.Aes, CryptoAlgorithm.Twofish, CryptoAlgorithm.Serpent } };
            yield return new object[] { CryptoAlgorithm.SerpentAes, new[] { CryptoAlgorithm.Serpent, CryptoAlgorithm.Aes } };
            yield return new object[] { CryptoAlgorithm.SerpentTwofishAes, new[] { CryptoAlgorithm.Serpent, CryptoAlgorithm.Twofish, CryptoAlgorithm.Aes } };
            yield return new object[] { CryptoAlgorithm.TwofishSerpent, new[] { CryptoAlgorithm.Twofish, CryptoAlgorithm.Serpent } };
            yield return new object[] { CryptoAlgorithm.CamelliaSerpent, new[] { CryptoAlgorithm.Camellia, CryptoAlgorithm.Serpent } };
        }

        [Theory]
        [MemberData(nameof(DecryptOrderCases))]
        public void GetDecryptOrder_ReturnsExpectedSequence(CryptoAlgorithm algorithm, CryptoAlgorithm[] expected)
        {
            var actual = (CryptoAlgorithm[])InvokeCascadeDefinitions("GetDecryptOrder", algorithm);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(DecryptOrderCases))]
        public void GetComponentCount_MatchesDecryptOrderLength(CryptoAlgorithm algorithm, CryptoAlgorithm[] expected)
        {
            var actual = (int)InvokeCascadeDefinitions("GetComponentCount", algorithm);
            Assert.Equal(expected.Length, actual);
        }

        [Fact]
        public void Decrypt_AesTwofishSerpentCascade_MatchesManuallyChainedSingleCipherDecrypts()
        {
            // 3 components x 32 bytes each. Every byte is distinct across the whole 96-byte range,
            // so a key-segment mixup between components would change the result.
            var dataKey = new byte[96];
            var tweakKey = new byte[96];
            for (var i = 0; i < 96; i++)
            {
                dataKey[i] = (byte)i;
                tweakKey[i] = (byte)(255 - i);
            }
            var cipherText = new byte[32]; // Two 16-byte blocks.
            for (var i = 0; i < cipherText.Length; i++)
            {
                cipherText[i] = (byte)(0xA5 ^ i);
            }
            const long dataUnitNumber = 7L;

            // Key segments are laid out in encryption/array order, the reverse of decrypt order:
            // for AES-Twofish-Serpent (decrypt order Aes, Twofish, Serpent) that is Serpent,
            // Twofish, Aes - so segment 0 => Serpent, segment 1 => Twofish, segment 2 => Aes.
            var serpentData = dataKey[0..32];
            var serpentTweak = tweakKey[0..32];
            var twofishData = dataKey[32..64];
            var twofishTweak = tweakKey[32..64];
            var aesData = dataKey[64..96];
            var aesTweak = tweakKey[64..96];

            // Decryption is applied Aes, then Twofish, then Serpent - the display name's own order.
            var afterAes = InvokeSingleCipher("XtsAesCipher", cipherText, aesData, aesTweak, dataUnitNumber);
            var afterTwofish = InvokeSingleCipher("XtsTwofishCipher", afterAes, twofishData, twofishTweak, dataUnitNumber);
            var expected = InvokeSingleCipher("XtsSerpentCipher", afterTwofish, serpentData, serpentTweak, dataUnitNumber);

            var actual = InvokeSelectorDecrypt(CryptoAlgorithm.AesTwofishSerpent, cipherText, dataKey, tweakKey, dataUnitNumber);

            Assert.Equal(expected, actual);
        }

        private static object InvokeCascadeDefinitions(string methodName, CryptoAlgorithm algorithm)
        {
            var method = GetInternalType("CascadeDefinitions").GetMethod(methodName, BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException($"CascadeDefinitions.{methodName} method not found.");
            return method.Invoke(null, new object[] { algorithm })!;
        }

        private static byte[] InvokeSingleCipher(string typeName, byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var method = GetInternalType(typeName).GetMethod("Decrypt", BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException($"{typeName}.Decrypt method not found.");
            return (byte[])method.Invoke(null, new object[] { cipherText, dataKey, tweakKey, dataUnitNumber })!;
        }

        private static byte[] InvokeSelectorDecrypt(CryptoAlgorithm algorithm, byte[] cipherText, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            var method = GetInternalType("XtsCipherSelector").GetMethod("Decrypt", BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException("XtsCipherSelector.Decrypt method not found.");
            return (byte[])method.Invoke(null, new object[] { algorithm, cipherText, dataKey, tweakKey, dataUnitNumber })!;
        }

        private static Type GetInternalType(string name)
        {
            return Array.Find(typeof(HeaderParser).Assembly.GetTypes(), t => t.Name == name)
                   ?? throw new InvalidOperationException($"{name} type not found.");
        }
    }
}
