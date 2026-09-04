using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for <see cref="SectorDecryptor"/> against the provided VeraCrypt test container
    /// "Test Data\AES_SHA-512_NTFS.hc" (see <see cref="TestContainers.AesNtfs"/>). Expected sector
    /// bytes below were captured directly from that container using the correct password and are
    /// specific to this file.
    ///
    /// SectorDecryptor.CreateAsync's argument guards (null file/header, missing file) throw
    /// synchronously, immediately - unlike VeraCryptContainer.OpenAsync's file-not-found check, this
    /// one lives directly in the non-async CreateAsync wrapper, not nested inside another async
    /// method. The same is true of DecryptSectorAsync/ReadDecryptedAsync's range checks. All tests
    /// below still use Assert.ThrowsAsync uniformly rather than asserting that distinction directly:
    /// xUnit's analyzer forbids Assert.Throws on any call that returns a Task, and ThrowsAsync
    /// correctly catches the exception either way.
    /// </summary>
    public class SectorDecryptorTests
    {
        // Sector 0 is the NTFS boot sector: jump instruction EB 52 90, OEM ID "NTFS    ", and the
        // 0x55 0xAA boot signature as the last two bytes.
        private const string ExpectedSector0Hex =
            "EB52904E5446532020202000020800000000000000F8000001000100000800000000000080000000FF2500000000000095010000000000000200000000000000F600000001000000E201BF0842BF087400000000FA33C08ED0BC007CFB68C0071F1E686600CB88160E0066813E03004E5446537515B441BBAA55CD13720C81FB55AA7506F7C101007503E9DD001E83EC18681A00B4488A160E008BF4161FCD139F83C4189E581F72E13B060B0075DBA30F00C12E0F00041E5A33DBB900202BC866FF06110003160F008EC2FF061600E84B002BC877EFB800BBCD1A6623C0752D6681FB54435041752481F90201721E166807BB166852111668090066536653665516161668B80166610E07CD1A33C0BF0A13B9F60CFCF3AAE9FE01909066601E0666A111006603061C001E66680000000066500653680100681000B4428A160E00161F8BF4CD1366595B5A665966591F0F82160066FF06110003160F008EC2FF0E160075BC071F6661C3A1F601E80900A1FA01E80300F4EBFD8BF0AC3C007409B40EBB0700CD10EBF2C30D0A41206469736B2072656164206572726F72206F63637572726564000D0A424F4F544D475220697320636F6D70726573736564000D0A5072657373204374726C2B416C742B44656C20746F20726573746172740D0A000000000000000000000000000000000000000000008A01A701BF01000055AA";

        private const string ExpectedSector1Hex =
            "070042004F004F0054004D00470052000400240049003300300000D400000024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000E9C0009005004E0054004C0044005200070042004F004F005400540047005400070042004F004F0054004E005800540000000000000000000000000000000000000000000D0A416E206F7065726174696E672073797374656D207761736E277420666F756E642E2054727920646973636F6E6E656374696E6720616E7920647269766573207468617420646F6E27740D0A636F6E7461696E20616E206F7065726174696E672073797374656D2E00000000000000000000000000000000000000009A02660FB7060B00660FB61E0D0066F7E366A35202668B0E400080F9000F8F0E00F6D966B80100000066D3E0EB089066A1520266F7E166A38602660FB71E0B006633D266F7F366A35602E8A204668B0E4E0266890E260266030E860266890E2A0266030E860266890E2E0266030E860266890E3E0266030E860266890E460266B890000000668B0E2602E89009660BC00F84BFFD66A3320266B8A0000000668B0E2A02E8770966A3360266B8B0000000668B0E2E02E8650966A33A0266A13202660BC00F848CFD67807808000F8583FD67668D50106703420467660FB6480C66890E920267668B4808";

        private static Task<SectorDecryptor> CreateDecryptorAsync()
        {
            return CreateDecryptorAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);
        }

        private static async Task<SectorDecryptor> CreateDecryptorAsync(FileInfo containerFile, string password, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm)
        {
            var header = await HeaderParser.ParseAsync(containerFile, password, algorithm, hashAlgorithm);
            return await SectorDecryptor.CreateAsync(containerFile, header);
        }

        [Fact]
        public async Task DecryptSectorAsync_Zero_ReturnsCorrectNtfsBootSector()
        {
            using var decryptor = await CreateDecryptorAsync();

            var sector = await decryptor.DecryptSectorAsync(0);

            Assert.Equal(ExpectedSector0Hex, Convert.ToHexString(sector));
        }

        [Fact]
        public async Task DecryptSectorAsync_One_MatchesKnownPlaintext()
        {
            using var decryptor = await CreateDecryptorAsync();

            var sector = await decryptor.DecryptSectorAsync(1);

            Assert.Equal(ExpectedSector1Hex, Convert.ToHexString(sector));
        }

        [Fact]
        public async Task DecryptSectorAsync_LastSector_MatchesNtfsBackupBootSector()
        {
            // NTFS stores a backup copy of the boot sector as the very last sector of the volume,
            // byte-for-byte identical to sector 0. This exercises a sector decrypted with a very
            // different (large) data-unit sequence number than sector 0.
            using var decryptor = await CreateDecryptorAsync();

            var lastSector = await decryptor.DecryptSectorAsync(decryptor.SectorCount - 1);

            Assert.Equal(ExpectedSector0Hex, Convert.ToHexString(lastSector));
        }

        [Fact]
        public async Task DecryptSectorAsync_DifferentSectors_ProduceDifferentPlaintext()
        {
            using var decryptor = await CreateDecryptorAsync();

            var sector0 = await decryptor.DecryptSectorAsync(0);
            var sector1 = await decryptor.DecryptSectorAsync(1);

            Assert.NotEqual(Convert.ToHexString(sector0), Convert.ToHexString(sector1));
        }

        [Fact]
        public async Task ReadDecryptedAsync_MultiSectorRange_MatchesConcatenationOfIndividualSectors()
        {
            using var decryptor = await CreateDecryptorAsync();

            var multi = await decryptor.ReadDecryptedAsync(0, 3 * decryptor.SectorSize);

            var expected = (await decryptor.DecryptSectorAsync(0))
                .Concat(await decryptor.DecryptSectorAsync(1))
                .Concat(await decryptor.DecryptSectorAsync(2))
                .ToArray();
            Assert.Equal(expected, multi);
        }

        [Fact]
        public async Task ReadDecryptedAsync_PartialReadWithinSector_MatchesSlice()
        {
            using var decryptor = await CreateDecryptorAsync();

            var partial = await decryptor.ReadDecryptedAsync(20, 10);

            var expected = (await decryptor.DecryptSectorAsync(0)).Skip(20).Take(10).ToArray();
            Assert.Equal(expected, partial);
        }

        [Fact]
        public async Task ReadDecryptedAsync_PartialReadCrossingSectorBoundary_MatchesSlice()
        {
            using var decryptor = await CreateDecryptorAsync();

            var spanning = await decryptor.ReadDecryptedAsync(decryptor.SectorSize - 5, 10);

            var expected = (await decryptor.DecryptSectorAsync(0)).Skip(decryptor.SectorSize - 5)
                .Concat((await decryptor.DecryptSectorAsync(1)).Take(5))
                .ToArray();
            Assert.Equal(expected, spanning);
        }

        [Fact]
        public async Task ReadDecryptedAsync_ZeroCount_ReturnsEmptyArray()
        {
            using var decryptor = await CreateDecryptorAsync();

            var result = await decryptor.ReadDecryptedAsync(0, 0);

            Assert.Empty(result);
        }

        [Fact]
        public async Task ReadDecryptedAsync_SingleFullSector_MatchesDecryptSectorAsync()
        {
            using var decryptor = await CreateDecryptorAsync();

            var viaRead = await decryptor.ReadDecryptedAsync(0, decryptor.SectorSize);
            var viaDecryptSector = await decryptor.DecryptSectorAsync(0);

            Assert.Equal(viaDecryptSector, viaRead);
        }

        [Fact]
        public async Task SectorCount_MatchesEncryptedAreaSizeDividedBySectorSize()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);
            using var decryptor = await SectorDecryptor.CreateAsync(TestContainers.AesNtfs.ContainerFile, header);

            Assert.Equal(header.EncryptedAreaSize / header.SectorSize, decryptor.SectorCount);
            Assert.Equal(header.SectorSize, decryptor.SectorSize);
        }

        [Fact]
        public async Task DecryptSectorAsync_NegativeIndex_ThrowsArgumentException()
        {
            using var decryptor = await CreateDecryptorAsync();

            await Assert.ThrowsAsync<ArgumentException>(() => decryptor.DecryptSectorAsync(-1));
        }

        [Fact]
        public async Task DecryptSectorAsync_IndexAtSectorCount_ThrowsArgumentException()
        {
            using var decryptor = await CreateDecryptorAsync();

            await Assert.ThrowsAsync<ArgumentException>(() => decryptor.DecryptSectorAsync(decryptor.SectorCount));
        }

        [Fact]
        public async Task ReadDecryptedAsync_NegativeOffset_ThrowsArgumentException()
        {
            using var decryptor = await CreateDecryptorAsync();

            await Assert.ThrowsAsync<ArgumentException>(() => decryptor.ReadDecryptedAsync(-1, 10));
        }

        [Fact]
        public async Task ReadDecryptedAsync_NegativeCount_ThrowsArgumentException()
        {
            using var decryptor = await CreateDecryptorAsync();

            await Assert.ThrowsAsync<ArgumentException>(() => decryptor.ReadDecryptedAsync(0, -1));
        }

        [Fact]
        public async Task ReadDecryptedAsync_RangeExtendingBeyondEncryptedArea_ThrowsArgumentException()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);
            using var decryptor = await SectorDecryptor.CreateAsync(TestContainers.AesNtfs.ContainerFile, header);

            await Assert.ThrowsAsync<ArgumentException>(() => decryptor.ReadDecryptedAsync(header.EncryptedAreaSize - 1, 2));
        }

        [Fact]
        public async Task CreateAsync_NullFileInfo_ThrowsArgumentNullException()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            await Assert.ThrowsAsync<ArgumentNullException>(() => SectorDecryptor.CreateAsync((FileInfo)null!, header));
        }

        [Fact]
        public async Task CreateAsync_NullStringPath_ThrowsArgumentNullException()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            await Assert.ThrowsAsync<ArgumentNullException>(() => SectorDecryptor.CreateAsync((string)null!, header));
        }

        [Fact]
        public async Task CreateAsync_NullHeader_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => SectorDecryptor.CreateAsync(TestContainers.AesNtfs.ContainerFile, null!));
        }

        [Fact]
        public async Task CreateAsync_NonExistentFile_ThrowsArgumentException()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);
            var missingPath = Path.Combine(TestContainers.AesNtfs.ContainerFile.DirectoryName!, "does-not-exist.hc");

            await Assert.ThrowsAsync<ArgumentException>(() => SectorDecryptor.CreateAsync(missingPath, header));
        }

        [Fact]
        public async Task DecryptSectorAsync_DoesNotAllocateMemoryProportionalToContainerSize()
        {
            // The container is ~5 MB; if DecryptSectorAsync pre-decrypted (or otherwise touched) the
            // whole container, allocations would be on that order. A single-sector decrypt should
            // allocate at most a handful of small, sector-sized buffers. Uses process-wide
            // GC.GetTotalAllocatedBytes() rather than GetAllocatedBytesForCurrentThread(), since the
            // actual decrypt work now runs on a thread-pool thread via Task.Run, not the calling
            // thread.
            using var decryptor = await CreateDecryptorAsync();
            await decryptor.DecryptSectorAsync(0); // warm up JIT/first-call overhead before measuring

            var before = GC.GetTotalAllocatedBytes(precise: true);
            await decryptor.DecryptSectorAsync(2);
            var allocated = GC.GetTotalAllocatedBytes(precise: true) - before;

            Assert.True(allocated < 200_000, $"Expected well under 200,000 bytes allocated, got {allocated}.");
        }
    }
}
