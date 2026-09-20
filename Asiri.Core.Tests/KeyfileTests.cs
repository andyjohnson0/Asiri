using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for keyfile support: the pool-mixing algorithm itself, via a hand-computed known-answer
    /// result, and both OpenAsync overloads' end-to-end behaviour against real VeraCrypt containers
    /// secured with one or more keyfiles, an empty password, and a long password. Like PIM, VeraCrypt
    /// never stores keyfiles in the header and never searches for them, so the negative cases here
    /// use single wrong guesses, not exhaustive searches - none of these tests need the Integration
    /// category.
    /// </summary>
    public class KeyfileTests
    {
        /// <summary>
        /// Validates KeyfileMixer.Apply directly against a hand-computed known-answer result,
        /// independent of any container: password "AB" (2 bytes, so a 64-byte pool), one keyfile
        /// containing the three bytes 0x01, 0x02, 0x03. The expected bytes were computed by an
        /// independent, from-scratch PowerShell implementation of the same algorithm - not derived
        /// from or copied out of Asiri's own KeyfileMixer - which was itself cross-checked against
        /// the standard published CRC-32 test vector (CRC32("123456789") = 0xCBF43926) before being
        /// trusted to compute this result.
        /// </summary>
        [Fact]
        public void Apply_KnownAnswer_MatchesIndependentlyComputedResult()
        {
            const string expectedHex =
                "9B3C20E44933BD6DAA437FE200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            var expected = Convert.FromHexString(expectedHex);
            Assert.Equal(64, expected.Length);

            var passwordBytes = Encoding.UTF8.GetBytes("AB");
            var keyFilePath = Path.Combine(Path.GetTempPath(), "asiri-keyfile-kat-" + Guid.NewGuid().ToString("N") + ".bin");
            File.WriteAllBytes(keyFilePath, new byte[] { 0x01, 0x02, 0x03 });
            try
            {
                var actual = InvokeApply(passwordBytes, new[] { new FileInfo(keyFilePath) });
                Assert.Equal(expected, actual);
            }
            finally
            {
                File.Delete(keyFilePath);
            }
        }

        [Fact]
        public void Apply_NoKeyFiles_ReturnsPasswordBytesUnchanged()
        {
            var passwordBytes = Encoding.UTF8.GetBytes("whatever");
            Assert.Same(passwordBytes, InvokeApply(passwordBytes, null!));
        }

        public static IEnumerable<object[]> KeyfileFixtures()
        {
            yield return new object[] { TestContainers.AesKf1ExFat };
            yield return new object[] { TestContainers.AesKf1EmptyPasswordExFat };
            yield return new object[] { TestContainers.AesKf1Kf2ExFat };
            yield return new object[] { TestContainers.AesKf1LongPasswordExFat };
        }

        [Theory]
        [MemberData(nameof(KeyfileFixtures))]
        public async Task OpenAsync_ExplicitParameters_WithCorrectKeyFiles_OpensContainer(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                var testTxt = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await testTxt.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task OpenAsync_ExplicitParameters_WithoutKeyFile_ThrowsInvalidOperationException()
        {
            var fixture = TestContainers.AesKf1ExFat;
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm }));
        }

        [Fact]
        public async Task OpenAsync_ExplicitParameters_WithWrongKeyFile_ThrowsInvalidOperationException()
        {
            // AesKf1ExFat was created with Keyfile1.bin; supplying Keyfile2.bin instead is a wrong
            // keyfile, not a missing one - a single (correct algorithm, correct hash, correct
            // password, wrong keyfile) attempt costs one PBKDF2 call, not a search.
            var fixture = TestContainers.AesKf1ExFat;
            var wrongKeyFile = TestContainers.AesKf1Kf2ExFat.KeyFiles[1]; // Keyfile2.bin
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, KeyFiles = new[] { wrongKeyFile } }));
        }

        [Fact]
        public async Task OpenAsync_ExplicitParameters_MissingKeyFile_ThrowsInvalidOperationException()
        {
            var fixture = TestContainers.AesKf1ExFat;
            var missingKeyFile = new FileInfo(Path.Combine(fixture.ContainerFile.DirectoryName!, "does-not-exist.bin"));
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, KeyFiles = new[] { missingKeyFile } }));
            Assert.Contains("Unable to open keyfile", exception.Message);
        }

        [Fact]
        public async Task OpenAsync_ExplicitParameters_EmptyKeyFile_ThrowsArgumentException()
        {
            var fixture = TestContainers.AesKf1ExFat;
            var emptyKeyFilePath = Path.Combine(Path.GetTempPath(), "asiri-empty-keyfile-" + Guid.NewGuid().ToString("N") + ".bin");
            File.WriteAllBytes(emptyKeyFilePath, Array.Empty<byte>());
            try
            {
                var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
                    VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, KeyFiles = new[] { new FileInfo(emptyKeyFilePath) } }));
                Assert.Contains("empty", exception.Message, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                File.Delete(emptyKeyFilePath);
            }
        }

        [Fact]
        public async Task OpenAsync_ExplicitParameters_NullKeyFileEntry_ThrowsArgumentException()
        {
            var fixture = TestContainers.AesKf1ExFat;
            var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, KeyFiles = new FileInfo?[] { null }! }));
            Assert.Equal("keyFiles", exception.ParamName);
        }

        /// <summary>
        /// Proves the brute-force, password-only OpenAsync overload correctly threads the supplied
        /// keyfiles through the (algorithm, hash) search. AesKf1ExFat uses AES/SHA-512, both first in
        /// their respective enums, so this resolves in one attempt - no need for the Integration
        /// category.
        /// </summary>
        [Fact]
        public async Task OpenAsync_PasswordOnly_WithCorrectKeyFiles_DetectsAlgorithmAndOpensContainer()
        {
            var fixture = TestContainers.AesKf1ExFat;
            var container = await VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Pim = 0, KeyFiles = fixture.KeyFiles });
            try
            {
                Assert.Equal(fixture.Algorithm, container.Algorithm);
                Assert.Equal(fixture.HashAlgorithm, container.HashAlgorithm);
                var testTxt = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await testTxt.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        private static byte[] InvokeApply(byte[] passwordBytes, IEnumerable<FileInfo>? keyFiles)
        {
            var type = Array.Find(typeof(HeaderParser).Assembly.GetTypes(), t => t.Name == "KeyfileMixer")
                       ?? throw new InvalidOperationException("KeyfileMixer type not found.");
            var method = type.GetMethod("Apply", BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException("KeyfileMixer.Apply method not found.");
            return (byte[])method.Invoke(null, new object?[] { passwordBytes, keyFiles })!;
        }
    }
}
