using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for OpenOptions.HeaderPreference / OpenResult.HeaderType - explicit control over which
    /// header region OpenAsync uses. Verified against VeraCrypt's own source
    /// (Core/MountOptions.h's UseBackupHeaders, Volume/Volume.cpp's Volume::Open): an explicit choice
    /// tries only that one region, with no fallback to the other - unlike HeaderType.Auto (the
    /// default), which keeps this library's existing always-fall-back-to-backup behaviour.
    /// </summary>
    public class HeaderPreferenceTests
    {
        /// <summary>
        /// Overwrites the primary header region of a container file with random bytes, so it can
        /// never decrypt successfully under any algorithm/hash combination - leaving the backup
        /// region, well outside this range, untouched and still valid. Used to prove the
        /// Auto-vs-explicit fallback distinction against a real container, not a synthetic one.
        /// </summary>
        private static void CorruptPrimaryHeader(FileInfo file)
        {
            var garbage = new byte[HeaderParser.HeaderRegionSize];
            new Random(12345).NextBytes(garbage);

            using var stream = file.Open(FileMode.Open, FileAccess.Write, FileShare.None);
            stream.Write(garbage, 0, garbage.Length);
        }

        [Fact]
        public async Task OpenAsync_Default_ReportsPrimaryHeaderType()
        {
            var fixture = TestContainers.AesNtfs;
            var result = await VeraCryptContainer.OpenAsync(
                fixture.ContainerFile, fixture.Password,
                new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm });
            try
            {
                Assert.Equal(HeaderType.Primary, result.HeaderType);
            }
            finally
            {
                result.Container.Close();
            }
        }

        [Fact]
        public async Task OpenAsync_ExplicitPrimary_SucceedsAndReportsPrimary()
        {
            var fixture = TestContainers.AesNtfs;
            var result = await VeraCryptContainer.OpenAsync(
                fixture.ContainerFile, fixture.Password,
                new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, HeaderPreference = HeaderType.Primary });
            try
            {
                Assert.Equal(HeaderType.Primary, result.HeaderType);
            }
            finally
            {
                result.Container.Close();
            }
        }

        [Fact]
        public async Task OpenAsync_ExplicitBackup_SucceedsReportsBackupAndReadsCorrectly()
        {
            var fixture = TestContainers.AesNtfs;
            var result = await VeraCryptContainer.OpenAsync(
                fixture.ContainerFile, fixture.Password,
                new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, HeaderPreference = HeaderType.Backup });
            try
            {
                Assert.Equal(HeaderType.Backup, result.HeaderType);

                // Sanity: the backup header decrypts the same data area, so an ordinary read should
                // work exactly as it would via the primary header.
                var files = await result.Container.Root.EnumerateFilesAsync();
                Assert.NotNull(files);
            }
            finally
            {
                result.Container.Close();
            }
        }

        [Fact]
        public async Task OpenAsync_PrimaryCorrupted_DefaultAutoFallsBackToBackup()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            CorruptPrimaryHeader(copy.File);

            var result = await VeraCryptContainer.OpenAsync(
                copy.File, fixture.Password,
                new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm });
            try
            {
                Assert.Equal(HeaderType.Backup, result.HeaderType);
            }
            finally
            {
                result.Container.Close();
            }
        }

        [Fact]
        public async Task OpenAsync_PrimaryCorrupted_ExplicitPrimary_ThrowsWithNoFallbackToBackup()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            CorruptPrimaryHeader(copy.File);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(
                    copy.File, fixture.Password,
                    new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, HeaderPreference = HeaderType.Primary }));
        }

        [Fact]
        public async Task OpenAsync_PrimaryCorrupted_ExplicitBackup_StillSucceeds()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            CorruptPrimaryHeader(copy.File);

            var result = await VeraCryptContainer.OpenAsync(
                copy.File, fixture.Password,
                new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, HeaderPreference = HeaderType.Backup });
            try
            {
                Assert.Equal(HeaderType.Backup, result.HeaderType);
            }
            finally
            {
                result.Container.Close();
            }
        }

        [Fact]
        public async Task OpenAsync_ExplicitBackup_FileTooSmallForBackupHeader_ThrowsDistinctMessage()
        {
            using var path = new TemporaryContainerPath();
            File.WriteAllBytes(path.File.FullName, new byte[1024]);

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(
                    path.File, "irrelevant-password",
                    new OpenOptions { Algorithm = CryptoAlgorithm.Aes, HashAlgorithm = HashAlgorithm.Sha512, HeaderPreference = HeaderType.Backup }));

            Assert.Contains("too small", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
    }
}
