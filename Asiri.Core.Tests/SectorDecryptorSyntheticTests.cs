using System;
using System.Diagnostics;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for <see cref="SectorDecryptor"/> that build synthetic containers (via
    /// <see cref="SyntheticContainerHelper"/>) rather than using the provided real container, to
    /// pin down behaviour the real 5 MB, 512-byte-sector container cannot exercise: the exact
    /// data-unit sequence number convention, chunking of sectors larger than 512 bytes, wrong-key
    /// behaviour, and non-pre-decryption over a very large container.
    /// </summary>
    public class SectorDecryptorSyntheticTests
    {
        [Fact]
        public async Task DecryptSectorAsync_UsesFileAbsoluteDataUnitNumbering()
        {
            // masterKeyScopeOffset is deliberately non-zero and not a multiple of the sector size
            // used elsewhere, so that "data unit number relative to the data area" (which would give
            // 0 for sector 0) and "data unit number relative to the start of the file" (which gives
            // masterKeyScopeOffset / 512 = 128 for sector 0) disagree.
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = 4 * sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 1);

            var plaintext = MakePattern(512, 0xAB);
            SyntheticContainerHelper.WriteEncryptedData(container, masterKeyScopeOffset, plaintext);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header);

            var decrypted = await decryptor.DecryptSectorAsync(0);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public async Task DecryptSectorAsync_DataAreaRelativeNumbering_DoesNotMatch()
        {
            // Encrypts using the *wrong* convention (data-unit number 0 at the start of the data
            // area, ignoring the file offset) and confirms SectorDecryptor - which uses the file's
            // absolute byte offset - does not accidentally decrypt it correctly. This shows the
            // preceding "correct" test is actually sensitive to the numbering convention.
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = 4 * sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 2);

            var plaintext = MakePattern(512, 0xCD);
            // Bytes are written at the correct file position (masterKeyScopeOffset), but encrypted
            // as if data unit 0 started there (dataUnitBaseOffset 0) rather than at its true file
            // offset - i.e. the "relative to the data area" convention this test disproves.
            SyntheticContainerHelper.WriteEncryptedData(container, masterKeyScopeOffset, dataUnitBaseOffset: 0, plaintext);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header);

            var decrypted = await decryptor.DecryptSectorAsync(0);

            Assert.NotEqual(plaintext, decrypted);
        }

        [Fact]
        public async Task DecryptSectorAsync_SectorLargerThan512Bytes_ChunksIntoIndependentDataUnits()
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 1536; // 3 x 512-byte AES-XTS data units
            const long encryptedAreaSize = 2 * sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 3);

            var plaintext = new byte[sectorSize];
            MakePattern(512, 0x11).CopyTo(plaintext, 0);
            MakePattern(512, 0x22).CopyTo(plaintext, 512);
            MakePattern(512, 0x33).CopyTo(plaintext, 1024);
            SyntheticContainerHelper.WriteEncryptedData(container, masterKeyScopeOffset, plaintext);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header);

            var decrypted = await decryptor.DecryptSectorAsync(0);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public async Task DecryptSectorAsync_WithWrongMasterKeys_ProducesIncorrectOutput()
        {
            // Simulates "wrong password" one layer down from HeaderParser: HeaderParser itself
            // rejects a wrong password outright (Stage 1), so the only way a mismatched key can
            // reach SectorDecryptor is if the header and the container data don't actually belong
            // together. This builds two containers with identical layout but different (random)
            // master keys, encrypts known plaintext into container A, then decrypts container A's
            // data using container B's header/keys.
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = 2 * sectorSize;

            using var containerA = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 10);
            using var containerB = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 20);

            var plaintext = MakePattern(512, 0xEE);
            SyntheticContainerHelper.WriteEncryptedData(containerA, masterKeyScopeOffset, plaintext);

            var wrongHeader = await HeaderParser.ParseAsync(containerB.Path, containerB.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(containerA.Path, wrongHeader);

            var decrypted = await decryptor.DecryptSectorAsync(0);

            Assert.NotEqual(plaintext, decrypted);
        }

        [Fact]
        public async Task DecryptSectorAsync_OnMultiGigabyteSparseContainer_CompletesQuickly()
        {
            // If DecryptSectorAsync pre-decrypted (or otherwise read) the whole container rather
            // than just the requested sector, this would take vastly longer than the bound below (or
            // fail outright). The file is created as a sparse file, so allocating it is near-instant
            // and consumes negligible real disk space.
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long fileLength = 4L * 1024 * 1024 * 1024; // 4 GB
            const long encryptedAreaSize = fileLength - masterKeyScopeOffset;
            const long targetSectorIndex = 3_000_000; // deep inside the 4 GB file

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 30);

            var plaintext = MakePattern(512, 0x77);
            SyntheticContainerHelper.WriteEncryptedData(
                container, masterKeyScopeOffset + targetSectorIndex * sectorSize, plaintext);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header);

            var stopwatch = Stopwatch.StartNew();
            var decrypted = await decryptor.DecryptSectorAsync(targetSectorIndex);
            stopwatch.Stop();

            Assert.Equal(plaintext, decrypted);
            Assert.True(stopwatch.ElapsedMilliseconds < 5000,
                $"Expected a single-sector decrypt of a 4 GB container to complete in well under 5 seconds, took {stopwatch.ElapsedMilliseconds} ms.");
        }

        private static byte[] MakePattern(int length, byte fill)
        {
            var b = new byte[length];
            for (var i = 0; i < length; i++)
            {
                b[i] = (byte)(fill ^ (i & 0xFF));
            }
            return b;
        }

    }
}
