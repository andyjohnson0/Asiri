using System;
using System.IO;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for the password-only <see cref="VeraCryptContainer.OpenAsync(FileInfo, string, System.Threading.CancellationToken)"/>
    /// overload: searching for the correct (CryptoAlgorithm, HashAlgorithm) combination and
    /// detecting the filesystem type automatically, without the caller specifying either - matching
    /// how VeraCrypt itself mounts a volume. Content correctness once opened is already covered by
    /// ContainerContentTests.cs via the explicit-parameters overload; these tests focus on the
    /// detection behaviour itself. Both OpenAsync overloads are declared <c>async</c>, so all
    /// exceptions - including argument-null checks - are deferred onto the returned Task rather than
    /// thrown synchronously; every test here uses Assert.ThrowsAsync accordingly.
    /// </summary>
    public class PasswordOnlyOpenAsyncTests
    {
        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task OpenAsync_WithCorrectPassword_DetectsFilesystemAndOpensContainer(TestContainers.ContainerFixture fixture)
        {
            var container = await VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password);
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
        public async Task OpenAsync_WrongPassword_ThrowsInvalidOperationException()
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(TestContainers.AesNtfs.ContainerFile, "definitely-wrong-password"));
        }

        [Fact]
        public async Task OpenAsync_NonExistentFile_ThrowsInvalidOperationException_NotMisreportedAsWrongPassword()
        {
            // Confirms the motivating design point for the DetectHeaderAsync refactor: a genuine I/O
            // failure must not be masked as "this combination didn't validate" after exhausting the
            // (CryptoAlgorithm, HashAlgorithm) search.
            var missing = new FileInfo(Path.Combine(TestContainers.AesNtfs.ContainerFile.DirectoryName!, "does-not-exist.hc"));

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(missing, "irrelevant"));

            Assert.Contains("Unable to open container file", exception.Message);
        }

        [Fact]
        public async Task OpenAsync_NullPath_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                VeraCryptContainer.OpenAsync(null!, TestContainers.AesNtfs.Password));
        }

        [Fact]
        public async Task OpenAsync_NullPassword_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                VeraCryptContainer.OpenAsync(TestContainers.AesNtfs.ContainerFile, null!));
        }

        [Fact]
        public async Task OpenAsync_HeaderDecryptsButVolumeHasNoRecognizableBootSector_ThrowsInvalidOperationException()
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 99);

            // An all-zero "boot sector": the header decrypts correctly (proving the password/keys are
            // right), but the decrypted data area has no 0x55 0xAA boot sector signature anywhere, so
            // filesystem detection should fail clearly rather than silently falling back to FAT.
            var notABootSector = new byte[sectorSize];
            SyntheticContainerHelper.WriteEncryptedData(container, masterKeyScopeOffset, notABootSector);

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(new FileInfo(container.Path), container.Password));

            Assert.Contains("boot sector", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
    }
}
