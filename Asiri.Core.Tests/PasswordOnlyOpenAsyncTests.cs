using System;
using System.Collections.Generic;
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
        /// <summary>
        /// A deliberately small subset of <see cref="TestContainers.All"/> for
        /// <see cref="OpenAsync_WithCorrectPassword_DetectsFilesystemAndOpensContainer"/>, rather than
        /// every registered fixture. That test drives the brute-force <c>OpenAsync</c> overload, which
        /// tries every (CryptoAlgorithm, HashAlgorithm) combination against the header until one
        /// validates - each attempt costs a full 500,000-iteration PBKDF2. Running it against all 16
        /// fixtures (10 algorithms x 4 hashes = up to 40 attempts each) made this one test method the
        /// dominant cost of the entire suite (over 15 minutes on its own), and every future algorithm
        /// this library adds will keep multiplying that cost further. The brute-force search logic
        /// itself does not vary per fixture, so exhaustively re-running it 16 times proves nothing
        /// that a well-chosen handful doesn't already prove. These five are chosen to each exercise a
        /// distinct, meaningful corner of the search space rather than being an arbitrary sample:
        /// - AesNtfs: NTFS boot-sector detection via the brute-force path (see remarks below, this is
        ///   the only test that exercises DetectFileSystemTypeAsync against a real NTFS container).
        /// - AesFat16: FAT boot-sector detection via the brute-force path, likewise the only coverage
        ///   of DetectFileSystemTypeAsync against a real FAT container.
        /// - AesWhirlpoolExFat: exFAT boot-sector detection, and a non-default hash algorithm, forcing
        ///   the inner hash loop to run to its third entry for every algorithm tried before this one.
        /// - SerpentTwofishAesExFat: a three-cipher cascade positioned 8th of 10 in the CryptoAlgorithm
        ///   enum, so finding it requires exhausting 7 wrong algorithms first.
        /// - CamelliaSerpentExFat: a two-cipher cascade positioned last (10th of 10) in the
        ///   CryptoAlgorithm enum - the worst-case algorithm-search depth this overload can hit.
        ///
        /// Even at five fixtures, the test this feeds is still slow enough (real PBKDF2 work, no way
        /// around it) that it is also tagged Category=Integration - see Asiri.Core.Tests/AGENT.md.
        /// </summary>
        /// <remarks>
        /// This is also the only place DetectFileSystemTypeAsync's real per-filesystem-type boot-sector
        /// sniffing is exercised against genuine containers: ContainerContentTests and
        /// VeraCryptContainerTests both open via the explicit-parameters overload, which takes
        /// FileSystemType directly and never calls DetectFileSystemTypeAsync at all. Do not narrow this
        /// list below one fixture per FileSystemType (NTFS, FAT, exFAT) without adding equivalent
        /// coverage elsewhere.
        /// </remarks>
        public static IEnumerable<object[]> BruteForceRepresentativeFixtures()
        {
            yield return new object[] { TestContainers.AesNtfs };
            yield return new object[] { TestContainers.AesFat16 };
            yield return new object[] { TestContainers.AesWhirlpoolExFat };
            yield return new object[] { TestContainers.SerpentTwofishAesExFat };
            yield return new object[] { TestContainers.CamelliaSerpentExFat };
        }

        [Trait("Category", "Integration")]
        [Theory]
        [MemberData(nameof(BruteForceRepresentativeFixtures))]
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

        /// <summary>
        /// Tagged Category=Integration rather than narrowed: unlike the fixture theory above, this
        /// test's whole point is to prove the brute-force search exhausts the *entire* real
        /// (CryptoAlgorithm, HashAlgorithm) grid against both header regions and fails cleanly - up to
        /// 80 real 500,000-iteration PBKDF2 attempts. Shrinking the algorithm/hash space here would
        /// mean it stops proving that. Excluding it from the default fast run, rather than reducing
        /// what it actually verifies, is the point of the Category trait - see Asiri.Core.Tests/AGENT.md.
        /// </summary>
        [Trait("Category", "Integration")]
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
