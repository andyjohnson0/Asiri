using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;
using Xunit;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for VeraCryptContainer.CreateAsync (issue #11). Unlike every other Integration test
    /// class, these don't start from a checked-in real-VeraCrypt fixture under "Test Data" - there is
    /// none to start from, since creating one from nothing is exactly the feature under test - so
    /// each test uses a TemporaryContainerPath instead.
    ///
    /// The core assertion pattern is create-close-reopen-verify, deliberately never writing through
    /// the handle CreateAsync itself returns: that would only prove the in-memory result is
    /// self-consistent, not that what actually landed on disk is a real, independently-openable
    /// VeraCrypt volume. Every test therefore closes the just-created container, reopens it through
    /// the same VeraCryptContainer.OpenAsync path every other test in this suite already exercises
    /// against real fixtures, writes a known file, closes again, and reopens once more read-only to
    /// confirm the write actually persisted rather than only existing in memory.
    ///
    /// This is still self-consistency, not independent validation - Asiri agrees with itself, the
    /// same way a real VeraCrypt was never asked to open any of these files. That is a materially
    /// weaker guarantee than the real-fixture tests elsewhere in this suite provide (see the README's
    /// own caution on write-path verification), and is noted here rather than left to read as
    /// stronger than it is.
    /// </summary>
    [Trait("Category", "Integration")]
    public class CreateContainerTests
    {
        // Comfortably above FatFileSystem.FormatPartition's own 8400-sector minimum (see
        // VeraCryptContainer.FormatFat) with margin, while still cheap to format and read back -
        // matching the scale of this project's own real, VeraCrypt-created FAT16/exFAT fixtures
        // (5 MiB), not a maximally-realistic container size.
        private const long Size = 8 * 1024 * 1024;

        private static async Task CreateWriteReopenVerifyAsync(
            CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, FileSystemType fileSystemType,
            string password = "a-create-test-password", int pim = 0, IReadOnlyList<FileInfo>? keyFiles = null,
            string? label = null, int? clusterSize = null)
        {
            using var tempPath = new TemporaryContainerPath();

            var created = await VeraCryptContainer.CreateAsync(
                tempPath.File, Size, password, algorithm, hashAlgorithm, fileSystemType, pim, keyFiles, label, clusterSize);
            created.Close();

            var container = await VeraCryptContainer.OpenAsync(
                tempPath.File, password, algorithm, hashAlgorithm, fileSystemType, pim, keyFiles,
                accessMode: ContainerAccessMode.ReadWrite);
            try
            {
                container.IsWritable = true;
                using var content = new MemoryStream(Encoding.UTF8.GetBytes("Hello, new container!"));
                var file = await container.Root.CreateFileAsync("test.txt", content);
                Assert.Equal("Hello, new container!", await file.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }

            // A separate, later open - proving the write in the block above was actually persisted to
            // disk, not merely visible through the same in-memory handle that made it.
            var reopened = await VeraCryptContainer.OpenAsync(
                tempPath.File, password, algorithm, hashAlgorithm, fileSystemType, pim, keyFiles);
            try
            {
                var file = await reopened.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, new container!", await file.ReadAllTextAsync());
            }
            finally
            {
                reopened.Close();
            }
        }

        [Fact]
        public Task CreateAsync_Ntfs_RoundTrips()
        {
            return CreateWriteReopenVerifyAsync(CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.Ntfs);
        }

        [Fact]
        public Task CreateAsync_Fat_RoundTrips()
        {
            return CreateWriteReopenVerifyAsync(CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.Fat);
        }

        [Fact]
        public Task CreateAsync_ExFat_RoundTrips()
        {
            return CreateWriteReopenVerifyAsync(CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.ExFat);
        }

        [Fact]
        public Task CreateAsync_CascadeCipher_RoundTrips()
        {
            // A 3-component cascade specifically - exercises GenerateMasterKeys/BuildNewHeaderPlaintext
            // with more than one component's worth of key material, matching why
            // ChangePasswordTests has an equivalent cascade-specific case.
            return CreateWriteReopenVerifyAsync(CryptoAlgorithm.SerpentTwofishAes, HashAlgorithm.Sha512, FileSystemType.ExFat);
        }

        [Fact]
        public Task CreateAsync_KeyfilesAndPim_RoundTrips()
        {
            // Reuses an existing fixture's keyfile purely as a source of bytes to mix into the
            // password - unrelated to that fixture's own container or credentials.
            var keyFiles = new[] { TestContainers.AesKf1ExFat.KeyFiles[0] };
            return CreateWriteReopenVerifyAsync(
                CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.ExFat,
                pim: 5, keyFiles: keyFiles);
        }

        [Fact]
        public Task CreateAsync_ClusterSize_ExFat_RoundTrips()
        {
            // 32 KiB - a legitimate exFAT cluster size (64 sectors), comfortably different from
            // whatever ExFatPartition.ComputeSectorsPerCluster would have picked by default for an
            // 8 MiB volume (4 KiB, per its own documented size tiers) - see FormatExFat.
            return CreateWriteReopenVerifyAsync(CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.ExFat, clusterSize: 32768);
        }

        [Theory]
        [InlineData(FileSystemType.Ntfs)]
        [InlineData(FileSystemType.Fat)]
        public async Task CreateAsync_ClusterSize_NtfsOrFat_Throws(FileSystemType fileSystemType)
        {
            // DiscUtils gives no way to override cluster size for either of these (verified against
            // its own source - see CreateAsync's own remarks on clusterSize), so a non-null value is
            // rejected outright rather than silently ignored.
            using var tempPath = new TemporaryContainerPath();

            await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.CreateAsync(
                    tempPath.File, Size, "a-create-test-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, fileSystemType,
                    clusterSize: 4096));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-4096)]
        [InlineData(500)]   // not a power of two
        [InlineData(256)]   // a power of two, but below the fixed 512-byte sector size
        public async Task CreateAsync_ClusterSize_Invalid_Throws(int clusterSize)
        {
            using var tempPath = new TemporaryContainerPath();

            await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.CreateAsync(
                    tempPath.File, Size, "a-create-test-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.ExFat,
                    clusterSize: clusterSize));
        }

        [Fact]
        public async Task CreateAsync_UnusedHeaderRegions_AreFilledWithRandomData()
        {
            // 512 = HeaderParser.HeaderRegionSize, 131072 = HeaderParser.DataAreaOffset /
            // HeaderParser.BackupHeaderOffsetFromEnd (internal - re-stated here rather than
            // referenced, matching this project's convention of not granting InternalsVisibleTo to
            // the test assembly). Per VeraCrypt's own Volume Format Specification, the space between
            // each 512-byte header region and the area where a hidden volume's own header could
            // reside (both on the primary side, before the data area, and the backup side, before
            // end-of-file) contains random data in every genuine VeraCrypt volume, precisely so an
            // observer can never tell whether that space holds a hidden volume or nothing at all.
            using var tempPath = new TemporaryContainerPath();

            var container = await VeraCryptContainer.CreateAsync(
                tempPath.File, Size, "a-create-test-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.Ntfs);
            container.Close();

            using var stream = tempPath.File.OpenRead();

            var primaryUnusedRegion = ReadBytesAt(stream, 512, 131072 - 512);
            Assert.False(IsAllSameByte(primaryUnusedRegion), "The unused space after the primary header was not filled with random data.");

            var backupRegionOffset = Size - 131072;
            var backupUnusedRegion = ReadBytesAt(stream, backupRegionOffset + 512, 131072 - 512);
            Assert.False(IsAllSameByte(backupUnusedRegion), "The unused space after the backup header was not filled with random data.");
        }

        [Fact]
        public async Task CreateAsync_DataAreaFreeSpace_IsFilledWithRandomData()
        {
            // Per VeraCrypt's own Volume Format Specification, the entire data area - not just the
            // header-adjacent regions covered by CreateAsync_UnusedHeaderRegions_AreFilledWithRandomData
            // above - is filled with random data "right before volume formatting begins", so that
            // clusters a filesystem formatter never touches (i.e. anything it marks as free space)
            // still hold what looks like genuine ciphertext rather than the raw zero bytes an
            // untouched, newly-extended file would otherwise contain.
            using var tempPath = new TemporaryContainerPath();

            var container = await VeraCryptContainer.CreateAsync(
                tempPath.File, Size, "a-create-test-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.Ntfs);
            container.Close();

            using var stream = tempPath.File.OpenRead();

            // 131072 = HeaderParser.DataAreaOffset (see the note on the header-region test above for
            // why this is re-stated rather than referenced). An 8 MiB container's NTFS formatter only
            // ever touches metadata near the start and end of the data area, so 4 MiB in is free space
            // that only this random fill - not formatting - could ever have written to.
            var dataAreaOffset = 131072L;
            var freeSpaceRegion = ReadBytesAt(stream, dataAreaOffset + 4 * 1024 * 1024, 4096);
            Assert.False(IsAllSameByte(freeSpaceRegion), "Free space in the data area was not filled with random data.");
        }

        private static byte[] ReadBytesAt(Stream stream, long offset, int length)
        {
            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[length];
            var totalRead = 0;
            while (totalRead < length)
            {
                var read = stream.Read(buffer, totalRead, length - totalRead);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }
                totalRead += read;
            }
            return buffer;
        }

        private static bool IsAllSameByte(byte[] data)
        {
            foreach (var b in data)
            {
                if (b != data[0])
                {
                    return false;
                }
            }
            return true;
        }

        [Fact]
        public async Task CreateAsync_Label_SetsVolumeLabel()
        {
            using var tempPath = new TemporaryContainerPath();

            var container = await VeraCryptContainer.CreateAsync(
                tempPath.File, Size, "a-create-test-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512,
                FileSystemType.Ntfs, label: "ASIRITEST");
            try
            {
                // VeraCryptContainer has no public surface for the underlying filesystem's own volume
                // label - reflection over the private field, rather than InternalsVisibleTo, matching
                // this project's established convention (see ReadWriteTests' use of the same pattern
                // for _lifetime).
                var fileSystemField = typeof(VeraCryptContainer).GetField("_fileSystem", BindingFlags.NonPublic | BindingFlags.Instance);
                var fileSystem = fileSystemField!.GetValue(container);
                var volumeLabelProperty = fileSystem!.GetType().GetProperty("VolumeLabel", BindingFlags.Public | BindingFlags.Instance);
                var volumeLabel = (string)volumeLabelProperty!.GetValue(fileSystem)!;

                Assert.Equal("ASIRITEST", volumeLabel);
            }
            finally
            {
                container.Close();
            }
        }

        /// <summary>
        /// Every other round-trip test in this class opens with an explicitly-known fsType, which
        /// never calls DetectFileSystemTypeAsync at all - only the password-only auto-detecting
        /// OpenAsync overload (what ContainerBrowser's Open dialog actually always uses) inspects the
        /// raw boot sector bytes. This gap let a real bug through: DiscUtils' own from-scratch Format
        /// methods never write the standard PC boot-sector signature (0x55 0xAA at bytes 510-511)
        /// that every genuine FAT/NTFS/exFAT volume carries, so a freshly created container mounted
        /// fine in real VeraCrypt (the encryption was never the problem) but Windows Explorer couldn't
        /// read its contents, and this auto-detecting overload rejected it outright - caught only by
        /// manual testing, not by any test that existed before this one. Parameterized across every
        /// filesystem type, unlike the single-fsType checks elsewhere in this class, specifically
        /// because the fix (VeraCryptContainer.FormatFileSystemAsync stamping the signature after
        /// formatting) is shared code that could easily have been correct for one filesystem and not
        /// another.
        /// </summary>
        [Theory]
        [InlineData(FileSystemType.Ntfs)]
        [InlineData(FileSystemType.Fat)]
        [InlineData(FileSystemType.ExFat)]
        public async Task CreateAsync_ThenAutoDetectOpen_Succeeds(FileSystemType fileSystemType)
        {
            using var tempPath = new TemporaryContainerPath();
            var created = await VeraCryptContainer.CreateAsync(
                tempPath.File, Size, "a-create-test-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, fileSystemType);
            created.Close();

            var container = await VeraCryptContainer.OpenAsync(tempPath.File, "a-create-test-password");
            try
            {
                Assert.Equal(fileSystemType, container.FileSystemType);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task CreateAsync_WrongPassword_CannotOpen()
        {
            using var tempPath = new TemporaryContainerPath();

            var created = await VeraCryptContainer.CreateAsync(
                tempPath.File, Size, "the-real-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.ExFat);
            created.Close();

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(tempPath.File, "definitely-the-wrong-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.ExFat));
        }

        [Fact]
        public async Task CreateAsync_PathAlreadyExists_ThrowsAndLeavesFileUntouched()
        {
            using var copy = new TemporaryContainerCopy(TestContainers.AesNtfs.ContainerFile);
            var originalBytes = await File.ReadAllBytesAsync(copy.File.FullName);

            await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.CreateAsync(
                    copy.File, Size, "a-create-test-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.Ntfs));

            Assert.Equal(originalBytes, await File.ReadAllBytesAsync(copy.File.FullName));
        }

        [Fact]
        public async Task CreateAsync_SizeTooSmall_ThrowsAndCreatesNoFile()
        {
            using var tempPath = new TemporaryContainerPath();

            await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.CreateAsync(
                    tempPath.File, size: 262144, "a-create-test-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.Ntfs));

            tempPath.File.Refresh();
            Assert.False(tempPath.File.Exists);
        }

        [Fact]
        public async Task CreateAsync_FilesystemMinimumNotMet_ThrowsAndDeletesPartialFile()
        {
            // Bigger than TotalHeaderOverheadSize (so CreateAsync's own upfront check passes) but far
            // below FAT's own 8400-sector minimum - proving the DiscUtils-level rejection is caught,
            // wrapped clearly, and that the partially-created file is cleaned up rather than left
            // behind looking like a real container.
            using var tempPath = new TemporaryContainerPath();

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.CreateAsync(
                    tempPath.File, size: 300000, "a-create-test-password", CryptoAlgorithm.Aes, HashAlgorithm.Sha512, FileSystemType.Fat));

            tempPath.File.Refresh();
            Assert.False(tempPath.File.Exists);
        }
    }
}
