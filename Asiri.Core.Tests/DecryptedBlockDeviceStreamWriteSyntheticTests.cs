using System;
using System.IO;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for DecryptedBlockDeviceStream's write path, using synthetic containers - see
    /// SectorDecryptorWriteSyntheticTests for why real test containers are never used for write
    /// testing. Complements the existing DecryptedBlockDeviceStreamTests (read/seek, against the real
    /// AES_SHA-512_NTFS.hc fixture), which is unchanged and untouched by this class.
    /// </summary>
    public class DecryptedBlockDeviceStreamWriteSyntheticTests
    {
        private static async Task<(SyntheticContainerHelper.Container container, SectorDecryptor decryptor, DecryptedBlockDeviceStream stream)> CreateWritableStreamAsync(int sectorCount, int seed)
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            var encryptedAreaSize = (long)sectorCount * sectorSize;

            var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            var decryptor = await SectorDecryptor.CreateAsync(container.Path, header, canWrite: true);
            return (container, decryptor, new DecryptedBlockDeviceStream(decryptor));
        }

        [Fact]
        public async Task CanWrite_WhenDecryptorOpenedWritable_IsTrue()
        {
            var (container, _, stream) = await CreateWritableStreamAsync(sectorCount: 1, seed: 200);
            using (container)
            using (stream)
            {
                Assert.True(stream.CanWrite);
            }
        }

        [Fact]
        public async Task Write_ThenReadBack_RoundTrips()
        {
            var (container, _, stream) = await CreateWritableStreamAsync(sectorCount: 1, seed: 201);
            using (container)
            using (stream)
            {
                var data = MakePattern(512, 0x5A);

                stream.Write(data, 0, data.Length);
                stream.Position = 0;
                var readBack = new byte[512];
                var bytesRead = stream.Read(readBack, 0, readBack.Length);

                Assert.Equal(512, bytesRead);
                Assert.Equal(data, readBack);
            }
        }

        [Fact]
        public async Task Write_UnalignedWithinSector_PreservesSurroundingBytes()
        {
            var (container, decryptor, stream) = await CreateWritableStreamAsync(sectorCount: 1, seed: 202);
            using (container)
            using (stream)
            {
                var baseline = MakePattern(512, 0x11);
                stream.Write(baseline, 0, baseline.Length);

                stream.Position = 20;
                var patch = MakePattern(10, 0xFF);
                stream.Write(patch, 0, patch.Length);

                var afterPatch = await decryptor.DecryptSectorAsync(0);
                Assert.Equal(patch, afterPatch[20..30]);
                Assert.Equal(baseline[0..20], afterPatch[0..20]);
                Assert.Equal(baseline[30..], afterPatch[30..]);
            }
        }

        [Fact]
        public async Task Write_AdvancesPositionByCountWritten()
        {
            var (container, _, stream) = await CreateWritableStreamAsync(sectorCount: 1, seed: 203);
            using (container)
            using (stream)
            {
                var data = MakePattern(100, 0x33);
                stream.Write(data, 0, data.Length);

                Assert.Equal(100, stream.Position);
            }
        }

        [Fact]
        public async Task Write_BeyondEndOfStream_ThrowsIOException()
        {
            var (container, _, stream) = await CreateWritableStreamAsync(sectorCount: 1, seed: 204);
            using (container)
            using (stream)
            {
                stream.Position = stream.Length - 5;
                Assert.Throws<IOException>(() => stream.Write(new byte[10], 0, 10));
            }
        }

        [Fact]
        public async Task Write_ZeroCount_DoesNotMovePosition()
        {
            var (container, _, stream) = await CreateWritableStreamAsync(sectorCount: 1, seed: 205);
            using (container)
            using (stream)
            {
                stream.Position = 42;
                stream.Write(Array.Empty<byte>(), 0, 0);

                Assert.Equal(42, stream.Position);
            }
        }

        [Fact]
        public async Task Write_NullBuffer_ThrowsArgumentNullException()
        {
            var (container, _, stream) = await CreateWritableStreamAsync(sectorCount: 1, seed: 206);
            using (container)
            using (stream)
            {
                Assert.Throws<ArgumentNullException>(() => stream.Write(null!, 0, 10));
            }
        }

        [Fact]
        public async Task Write_NegativeOffset_ThrowsArgumentException()
        {
            var (container, _, stream) = await CreateWritableStreamAsync(sectorCount: 1, seed: 207);
            using (container)
            using (stream)
            {
                Assert.Throws<ArgumentException>(() => stream.Write(new byte[10], -1, 5));
            }
        }

        [Fact]
        public async Task Write_WhenStreamNotWritable_ThrowsNotSupportedException()
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long encryptedAreaSize = sectorSize;

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength: masterKeyScopeOffset + encryptedAreaSize, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 208);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            var decryptor = await SectorDecryptor.CreateAsync(container.Path, header); // not writable
            using var stream = new DecryptedBlockDeviceStream(decryptor);

            Assert.False(stream.CanWrite);
            Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
        }

        [Fact]
        public async Task SetLength_ThrowsNotSupportedException_EvenWhenWritable()
        {
            // Confirms this is unconditional - the volume's encrypted data area size is fixed by the
            // container format, not merely restricted by read-only status.
            var (container, _, stream) = await CreateWritableStreamAsync(sectorCount: 1, seed: 209);
            using (container)
            using (stream)
            {
                Assert.Throws<NotSupportedException>(() => stream.SetLength(100));
            }
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
