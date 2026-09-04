using System;
using System.IO;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for <see cref="HeaderParser"/> against the provided VeraCrypt test container
    /// "Test Data\AES_SHA-512_NTFS.hc" (see <see cref="TestContainers.AesNtfs"/>). Expected field
    /// values below were captured directly from that container using the correct password and are
    /// specific to this file.
    /// </summary>
    public class HeaderParserTests
    {
        private const string WrongPassword = "definitely-not-the-right-password";

        private const string ExpectedMagic = "VERA";
        private const int ExpectedVersion = 5;
        private const int ExpectedMinRequiredVersion = 267;
        private const int ExpectedSectorSize = 512;
        private const long ExpectedVolumeSize = 4980736;
        private const long ExpectedHiddenVolumeSize = 0;
        private const long ExpectedMasterKeyScopeOffset = 131072;
        private const long ExpectedEncryptedAreaSize = 4980736;
        private const int ExpectedFlags = 0;
        private const string ExpectedMasterKeyHex = "5EDF5F6B2BEAF57889C1A48311448CFA4520DAFC2D34EE86859B1F2953EC5C78";
        private const string ExpectedSecondaryKeyHex = "1D34B39DED93218A9CC212EA8964D7A6DFD047B14C180D98ABD486D313280825";

        [Fact]
        public async Task ParseAsync_ValidContainer_ReturnsExpectedMagic()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.Equal(ExpectedMagic, header.Magic);
        }

        [Fact]
        public async Task ParseAsync_ValidContainer_ReturnsExpectedVersion()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.Equal(ExpectedVersion, header.Version);
        }

        [Fact]
        public async Task ParseAsync_ValidContainer_ReturnsExpectedSectorSize()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.Equal(ExpectedSectorSize, header.SectorSize);
        }

        [Fact]
        public async Task ParseAsync_ValidContainer_CrcIsValid()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.True(header.CrcValid);
        }

        [Fact]
        public async Task ParseAsync_ValidContainer_IsNotFromBackup()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.False(header.FromBackup);
        }

        [Fact]
        public async Task ParseAsync_ValidContainer_ReturnsExpectedMetadataFields()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.Equal(ExpectedMinRequiredVersion, header.MinRequiredVersion);
            Assert.Equal(ExpectedVolumeSize, header.VolumeSize);
            Assert.Equal(ExpectedHiddenVolumeSize, header.HiddenVolumeSize);
            Assert.Equal(ExpectedMasterKeyScopeOffset, header.MasterKeyScopeOffset);
            Assert.Equal(ExpectedEncryptedAreaSize, header.EncryptedAreaSize);
            Assert.Equal(ExpectedFlags, header.Flags);
        }

        [Fact]
        public async Task ParseAsync_ValidContainer_ReturnsExpectedMasterKeys()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.Equal(ExpectedMasterKeyHex, Convert.ToHexString(header.MasterKey));
            Assert.Equal(ExpectedSecondaryKeyHex, Convert.ToHexString(header.SecondaryKey));
        }

        [Fact]
        public async Task ParseAsync_ValidContainer_SetsAlgorithmOnHeader()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.Equal(TestContainers.AesNtfs.Algorithm, header.Algorithm);
        }

        [Fact]
        public async Task ParseAsync_SerpentContainer_DecryptsAndSetsAlgorithmOnHeader()
        {
            var header = await HeaderParser.ParseAsync(
                TestContainers.SerpentExFat.ContainerFile, TestContainers.SerpentExFat.Password,
                TestContainers.SerpentExFat.Algorithm, TestContainers.SerpentExFat.HashAlgorithm);

            Assert.True(header.CrcValid);
            Assert.Equal(CryptoAlgorithm.Serpent, header.Algorithm);
        }

        [Fact]
        public async Task ParseAsync_SerpentContainer_WithAesAlgorithmSpecified_FailsToDecode()
        {
            // The header itself doesn't record which algorithm to use - the caller must know, or
            // search - so asking HeaderParser to decrypt a genuinely Serpent-encrypted header as AES
            // must fail cleanly (CRC won't validate against XTS-AES-decrypted garbage), not silently
            // produce a wrong-but-CRC-passing result. Confirms the two algorithms are genuinely
            // distinct at the header-decryption layer, not just distinguished by a label.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                HeaderParser.ParseAsync(
                    TestContainers.SerpentExFat.ContainerFile, TestContainers.SerpentExFat.Password,
                    CryptoAlgorithm.Aes, TestContainers.SerpentExFat.HashAlgorithm));
        }

        [Fact]
        public async Task ParseAsync_TwofishContainer_DecryptsAndSetsAlgorithmOnHeader()
        {
            var header = await HeaderParser.ParseAsync(
                TestContainers.TwofishExFat.ContainerFile, TestContainers.TwofishExFat.Password,
                TestContainers.TwofishExFat.Algorithm, TestContainers.TwofishExFat.HashAlgorithm);

            Assert.True(header.CrcValid);
            Assert.Equal(CryptoAlgorithm.Twofish, header.Algorithm);
        }

        [Fact]
        public async Task ParseAsync_TwofishContainer_WithAesAlgorithmSpecified_FailsToDecode()
        {
            // See ParseAsync_SerpentContainer_WithAesAlgorithmSpecified_FailsToDecode: confirms
            // Twofish and AES are genuinely cryptographically distinct at the header-decryption
            // layer, not just distinguished by a label.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                HeaderParser.ParseAsync(
                    TestContainers.TwofishExFat.ContainerFile, TestContainers.TwofishExFat.Password,
                    CryptoAlgorithm.Aes, TestContainers.TwofishExFat.HashAlgorithm));
        }

        [Fact]
        public async Task ParseAsync_CamelliaContainer_DecryptsAndSetsAlgorithmOnHeader()
        {
            var header = await HeaderParser.ParseAsync(
                TestContainers.CamelliaExFat.ContainerFile, TestContainers.CamelliaExFat.Password,
                TestContainers.CamelliaExFat.Algorithm, TestContainers.CamelliaExFat.HashAlgorithm);

            Assert.True(header.CrcValid);
            Assert.Equal(CryptoAlgorithm.Camellia, header.Algorithm);
        }

        [Fact]
        public async Task ParseAsync_CamelliaContainer_WithAesAlgorithmSpecified_FailsToDecode()
        {
            // See ParseAsync_SerpentContainer_WithAesAlgorithmSpecified_FailsToDecode: confirms
            // Camellia and AES are genuinely cryptographically distinct at the header-decryption
            // layer, not just distinguished by a label.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                HeaderParser.ParseAsync(
                    TestContainers.CamelliaExFat.ContainerFile, TestContainers.CamelliaExFat.Password,
                    CryptoAlgorithm.Aes, TestContainers.CamelliaExFat.HashAlgorithm));
        }

        [Fact]
        public async Task ParseAsync_Sha256Container_DecryptsAndSetsAlgorithmOnHeader()
        {
            var header = await HeaderParser.ParseAsync(
                TestContainers.AesSha256ExFat.ContainerFile, TestContainers.AesSha256ExFat.Password,
                TestContainers.AesSha256ExFat.Algorithm, TestContainers.AesSha256ExFat.HashAlgorithm);

            Assert.True(header.CrcValid);
            Assert.Equal(CryptoAlgorithm.Aes, header.Algorithm);
        }

        [Fact]
        public async Task ParseAsync_Sha256Container_WithSha512Specified_FailsToDecode()
        {
            // Mirrors the CryptoAlgorithm distinctness tests above, but for HashAlgorithm: confirms
            // SHA-256 and SHA-512 derive genuinely different PBKDF2 keys - specifying the wrong hash
            // algorithm must fail cleanly (CRC won't validate), not silently produce a wrong result.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                HeaderParser.ParseAsync(
                    TestContainers.AesSha256ExFat.ContainerFile, TestContainers.AesSha256ExFat.Password,
                    TestContainers.AesSha256ExFat.Algorithm, HashAlgorithm.Sha512));
        }

        [Fact]
        public async Task ParseAsync_WhirlpoolContainer_DecryptsAndSetsAlgorithmOnHeader()
        {
            var header = await HeaderParser.ParseAsync(
                TestContainers.AesWhirlpoolExFat.ContainerFile, TestContainers.AesWhirlpoolExFat.Password,
                TestContainers.AesWhirlpoolExFat.Algorithm, TestContainers.AesWhirlpoolExFat.HashAlgorithm);

            Assert.True(header.CrcValid);
            Assert.Equal(CryptoAlgorithm.Aes, header.Algorithm);
        }

        [Fact]
        public async Task ParseAsync_WhirlpoolContainer_WithSha512Specified_FailsToDecode()
        {
            // Mirrors ParseAsync_Sha256Container_WithSha512Specified_FailsToDecode: confirms
            // Whirlpool and SHA-512 derive genuinely different PBKDF2 keys.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                HeaderParser.ParseAsync(
                    TestContainers.AesWhirlpoolExFat.ContainerFile, TestContainers.AesWhirlpoolExFat.Password,
                    TestContainers.AesWhirlpoolExFat.Algorithm, HashAlgorithm.Sha512));
        }

        [Fact]
        public async Task ParseAsync_Blake2s256Container_DecryptsAndSetsAlgorithmOnHeader()
        {
            var header = await HeaderParser.ParseAsync(
                TestContainers.AesBlake2s256ExFat.ContainerFile, TestContainers.AesBlake2s256ExFat.Password,
                TestContainers.AesBlake2s256ExFat.Algorithm, TestContainers.AesBlake2s256ExFat.HashAlgorithm);

            Assert.True(header.CrcValid);
            Assert.Equal(CryptoAlgorithm.Aes, header.Algorithm);
        }

        [Fact]
        public async Task ParseAsync_Blake2s256Container_WithSha512Specified_FailsToDecode()
        {
            // Mirrors ParseAsync_Sha256Container_WithSha512Specified_FailsToDecode: confirms
            // BLAKE2s-256 and SHA-512 derive genuinely different PBKDF2 keys.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                HeaderParser.ParseAsync(
                    TestContainers.AesBlake2s256ExFat.ContainerFile, TestContainers.AesBlake2s256ExFat.Password,
                    TestContainers.AesBlake2s256ExFat.Algorithm, HashAlgorithm.Sha512));
        }

        [Fact]
        public async Task ParseAsync_StringPathOverload_AndFileInfoOverload_ReturnEquivalentHeaders()
        {
            var fromString = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile.FullName, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);
            var fromFileInfo = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.Equal(fromString.Magic, fromFileInfo.Magic);
            Assert.Equal(fromString.Version, fromFileInfo.Version);
            Assert.Equal(fromString.SectorSize, fromFileInfo.SectorSize);
            Assert.Equal(Convert.ToHexString(fromString.MasterKey), Convert.ToHexString(fromFileInfo.MasterKey));
        }

        [Fact]
        public async Task ParseAsync_WrongPassword_ThrowsInvalidOperationException()
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, WrongPassword, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm));
        }

        [Fact]
        public async Task ParseAsync_NullStringPath_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => HeaderParser.ParseAsync((string)null!, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm));
        }

        [Fact]
        public async Task ParseAsync_NullFileInfoPath_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => HeaderParser.ParseAsync((FileInfo)null!, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm));
        }

        [Fact]
        public async Task ParseAsync_NullPassword_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, null!, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm));
        }

        [Fact]
        public async Task ParseAsync_NonExistentFile_ThrowsArgumentException()
        {
            var missingPath = Path.Combine(TestContainers.AesNtfs.ContainerFile.DirectoryName!, "does-not-exist.hc");

            await Assert.ThrowsAsync<ArgumentException>(() => HeaderParser.ParseAsync(missingPath, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm));
        }

        [Fact]
        public async Task ParseAsync_PrimaryHeaderCorrupted_FallsBackToBackupHeader()
        {
            using var corrupted = new CorruptedContainerCopy(TestContainers.AesNtfs.ContainerFile.FullName, corruptPrimary: true, corruptBackup: false);

            var header = await HeaderParser.ParseAsync(corrupted.Path, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);

            Assert.True(header.FromBackup);
            Assert.True(header.CrcValid);
            Assert.Equal(ExpectedMagic, header.Magic);
            Assert.Equal(ExpectedVersion, header.Version);
            Assert.Equal(ExpectedSectorSize, header.SectorSize);
            Assert.Equal(ExpectedMasterKeyHex, Convert.ToHexString(header.MasterKey));
        }

        [Fact]
        public async Task ParseAsync_PrimaryAndBackupHeaderCorrupted_ThrowsInvalidOperationException()
        {
            using var corrupted = new CorruptedContainerCopy(TestContainers.AesNtfs.ContainerFile.FullName, corruptPrimary: true, corruptBackup: true);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                HeaderParser.ParseAsync(corrupted.Path, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm));
        }

        [Fact]
        public async Task TryDecryptRegionAsync_CorrectCombination_ReturnsValidatedHeader()
        {
            var region = ReadPrimaryRegion(TestContainers.AesNtfs.ContainerFile);

            var header = await HeaderParser.TryDecryptRegionAsync(
                region, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, fromBackup: false);

            Assert.NotNull(header);
            Assert.Equal(ExpectedMagic, header!.Magic);
            Assert.True(header.CrcValid);
            Assert.False(header.FromBackup);
            Assert.Equal(TestContainers.AesNtfs.Algorithm, header.Algorithm);
            Assert.Equal(ExpectedMasterKeyHex, Convert.ToHexString(header.MasterKey));
        }

        [Fact]
        public async Task TryDecryptRegionAsync_WrongPassword_ReturnsNullRatherThanThrowing()
        {
            // The whole point of this method - unlike ParseAsync - is to let a caller cheaply try
            // many combinations without exception overhead per attempt.
            var region = ReadPrimaryRegion(TestContainers.AesNtfs.ContainerFile);

            var header = await HeaderParser.TryDecryptRegionAsync(
                region, WrongPassword, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, fromBackup: false);

            Assert.Null(header);
        }

        [Fact]
        public async Task TryDecryptRegionAsync_FromBackupTrue_IsReflectedOnReturnedHeader()
        {
            var region = ReadPrimaryRegion(TestContainers.AesNtfs.ContainerFile);

            // fromBackup here only labels the header; region content is unrelated to whether it
            // actually came from the backup location, but the label should still round-trip as given.
            var header = await HeaderParser.TryDecryptRegionAsync(
                region, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, fromBackup: true);

            Assert.NotNull(header);
            Assert.True(header!.FromBackup);
        }

        [Fact]
        public async Task TryDecryptRegionAsync_NullRegion_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                HeaderParser.TryDecryptRegionAsync(null!, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, fromBackup: false));
        }

        [Fact]
        public async Task TryDecryptRegionAsync_NullPassword_ThrowsArgumentNullException()
        {
            var region = ReadPrimaryRegion(TestContainers.AesNtfs.ContainerFile);

            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                HeaderParser.TryDecryptRegionAsync(region, null!, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, fromBackup: false));
        }

        [Fact]
        public async Task TryDecryptRegionAsync_WrongRegionLength_ThrowsArgumentException()
        {
            var tooShort = new byte[HeaderParser.HeaderRegionSize - 1];

            await Assert.ThrowsAsync<ArgumentException>(() =>
                HeaderParser.TryDecryptRegionAsync(tooShort, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, fromBackup: false));
        }

        [Fact]
        public async Task TryDecryptRegionAsync_UnsupportedAlgorithm_ThrowsArgumentException()
        {
            var region = ReadPrimaryRegion(TestContainers.AesNtfs.ContainerFile);

            await Assert.ThrowsAsync<ArgumentException>(() =>
                HeaderParser.TryDecryptRegionAsync(region, TestContainers.AesNtfs.Password, (CryptoAlgorithm)99, TestContainers.AesNtfs.HashAlgorithm, fromBackup: false));
        }

        private static byte[] ReadPrimaryRegion(FileInfo containerFile)
        {
            using var stream = containerFile.OpenRead();
            var buffer = new byte[HeaderParser.HeaderRegionSize];
            var totalRead = 0;
            while (totalRead < buffer.Length)
            {
                var read = stream.Read(buffer, totalRead, buffer.Length - totalRead);
                totalRead += read;
            }
            return buffer;
        }

        /// <summary>
        /// A temporary copy of the provided test container with its primary and/or backup header
        /// region zeroed out, used to exercise backup-header-fallback behaviour without ever
        /// modifying the original container file.
        /// </summary>
        private sealed class CorruptedContainerCopy : IDisposable
        {
            private const int HeaderRegionSize = 512;
            private const long BackupHeaderOffsetFromEnd = 131072;

            public string Path { get; }

            public CorruptedContainerCopy(string sourcePath, bool corruptPrimary, bool corruptBackup)
            {
                Path = System.IO.Path.GetTempFileName();
                File.Copy(sourcePath, Path, overwrite: true);

                using var stream = new FileStream(Path, FileMode.Open, FileAccess.Write);
                var zeros = new byte[HeaderRegionSize];

                if (corruptPrimary)
                {
                    stream.Seek(0, SeekOrigin.Begin);
                    stream.Write(zeros, 0, zeros.Length);
                }

                if (corruptBackup)
                {
                    stream.Seek(stream.Length - BackupHeaderOffsetFromEnd, SeekOrigin.Begin);
                    stream.Write(zeros, 0, zeros.Length);
                }
            }

            public void Dispose()
            {
                File.Delete(Path);
            }
        }
    }
}
