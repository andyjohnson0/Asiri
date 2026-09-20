using System;
using System.IO;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for SectorDecryptor's write path, using synthetic containers built by
    /// SyntheticContainerHelper - never the checked-in real test containers under "Test Data", which
    /// must stay untouched: they are shared read-path fixtures the whole suite depends on, and the
    /// "mutate a byte, watch a test fail" validation mechanism the README describes only works if
    /// they're never modified by anything but real VeraCrypt. SyntheticContainerHelper's files are
    /// temporary (Path.GetTempFileName()) and deleted on Dispose.
    ///
    /// Exercises the write path entirely through the public WriteDecryptedAsync - the internal
    /// EncryptAndWriteSector it calls for each affected sector isn't reachable from this project
    /// without reflection, and WriteDecryptedAsync is the real public entry point anyway. A write
    /// that happens to cover a whole sector exactly (as most tests below do, for simplicity) still
    /// exercises EncryptAndWriteSector's full encrypt-and-write logic; WriteDecryptedAsync's own
    /// read-modify-write wrapping around it is exercised separately below.
    /// </summary>
    public class SectorDecryptorWriteSyntheticTests
    {
        [Fact]
        public async Task WriteDecryptedAsync_WholeSector_ThenDecryptSector_RoundTrips()
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = 4 * sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 100);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header, canWrite: true);

            var plaintext = MakePattern(sectorSize, 0x5A);
            await decryptor.WriteDecryptedAsync(0, plaintext);

            var decrypted = await decryptor.DecryptSectorAsync(0);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public async Task WriteDecryptedAsync_ProducesSameCiphertextAsIndependentEncryption()
        {
            // The write-path counterpart to SectorDecryptorSyntheticTests' data-unit-numbering
            // checks: proves the encrypted bytes actually written to disk are byte-for-byte what an
            // independent (non-BouncyCastle, non-Asiri) AES-XTS implementation produces for the same
            // plaintext, keys, and data-unit number - not just that Asiri's own Encrypt and Decrypt
            // agree with each other, which a bug present identically in both could still satisfy.
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512; // exactly one AES-XTS data unit, keeping the comparison simple.
            const long encryptedAreaSize = 2 * sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 101);

            var plaintext = MakePattern(sectorSize, 0x99);

            // Reference ciphertext: written independently, at the real sector 0 file offset, so it
            // uses the same data-unit number Asiri's own write will use.
            SyntheticContainerHelper.WriteEncryptedData(container, masterKeyScopeOffset, plaintext);
            var expectedCiphertext = ReadRawBytes(container.Path, masterKeyScopeOffset, sectorSize);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using (var decryptor = await SectorDecryptor.CreateAsync(container.Path, header, canWrite: true))
            {
                await decryptor.WriteDecryptedAsync(0, plaintext);
            }

            var actualCiphertext = ReadRawBytes(container.Path, masterKeyScopeOffset, sectorSize);

            Assert.Equal(expectedCiphertext, actualCiphertext);
        }

        [Fact]
        public async Task WriteDecryptedAsync_UnalignedRangeWithinOneSector_PreservesSurroundingBytes()
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = 2 * sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 102);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header, canWrite: true);

            var baseline = MakePattern(sectorSize, 0x11);
            await decryptor.WriteDecryptedAsync(0, baseline);

            var patch = MakePattern(10, 0xFF);
            await decryptor.WriteDecryptedAsync(20, patch);

            var afterPatch = await decryptor.DecryptSectorAsync(0);

            Assert.Equal(patch, afterPatch[20..30]);
            Assert.Equal(baseline[0..20], afterPatch[0..20]);
            Assert.Equal(baseline[30..], afterPatch[30..]);
        }

        [Fact]
        public async Task WriteDecryptedAsync_SpanningTwoSectors_WritesBothSectorsCorrectly()
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = 3 * sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 103);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header, canWrite: true);

            var baselineSector0 = MakePattern(sectorSize, 0x11);
            var baselineSector1 = MakePattern(sectorSize, 0x22);
            await decryptor.WriteDecryptedAsync(0, baselineSector0);
            await decryptor.WriteDecryptedAsync(sectorSize, baselineSector1);

            // A write starting 10 bytes before the end of sector 0 and ending 10 bytes into sector 1.
            var patch = MakePattern(20, 0xEE);
            await decryptor.WriteDecryptedAsync(sectorSize - 10, patch);

            var afterSector0 = await decryptor.DecryptSectorAsync(0);
            var afterSector1 = await decryptor.DecryptSectorAsync(1);

            Assert.Equal(patch[0..10], afterSector0[(sectorSize - 10)..]);
            Assert.Equal(baselineSector0[0..(sectorSize - 10)], afterSector0[0..(sectorSize - 10)]);
            Assert.Equal(patch[10..20], afterSector1[0..10]);
            Assert.Equal(baselineSector1[10..], afterSector1[10..]);
        }

        [Fact]
        public async Task WriteDecryptedAsync_WhenNotOpenedWritable_ThrowsNotSupportedException()
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 104);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header); // canWrite defaults to false

            Assert.False(decryptor.CanWrite);
            await Assert.ThrowsAsync<NotSupportedException>(() => decryptor.WriteDecryptedAsync(0, new byte[10]));
        }

        [Fact]
        public async Task CreateAsync_WithCanWriteTrue_OpensFileExclusively()
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 106);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header, canWrite: true);

            // A second handle, even for read-only sharing, must be refused while the writable
            // decryptor holds the file open exclusively (FileShare.None) - matching how a real
            // mounted VeraCrypt volume locks its container file.
            Assert.Throws<IOException>(() => new FileStream(container.Path, FileMode.Open, FileAccess.Read, FileShare.Read));
        }

        [Fact]
        public async Task CreateAsync_WithCanWriteFalse_AllowsConcurrentReaders()
        {
            // Confirms the preceding test is actually about canWrite, not an accidental universal
            // exclusive lock - the existing read-only behaviour (shared read access) must be unchanged.
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 107);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            using var decryptor = await SectorDecryptor.CreateAsync(container.Path, header);

            var exception = Record.Exception(() =>
            {
                using var secondReader = new FileStream(container.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
            });

            Assert.Null(exception);
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

        private static byte[] ReadRawBytes(string path, long offset, int count)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            fs.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[count];
            var totalRead = 0;
            while (totalRead < count)
            {
                var read = fs.Read(buffer, totalRead, count - totalRead);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }
                totalRead += read;
            }
            return buffer;
        }
    }
}
