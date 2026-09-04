using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for <see cref="DecryptedBlockDeviceStream"/> against the provided VeraCrypt test
    /// container "Test Data\AES_SHA-512_NTFS.hc", covering the Stream contract (Length,
    /// Position/Seek, Read/Write behaviour) and equivalence with the underlying SectorDecryptor.
    ///
    /// DecryptedBlockDeviceStream itself stays a plain synchronous Stream - DiscUtils, its only real
    /// consumer, calls it synchronously and has no async awareness - so its own Read/Seek/Position
    /// tests below are unchanged. Only the setup helper changed, since HeaderParser.ParseAsync and
    /// SectorDecryptor.CreateAsync replace their former synchronous equivalents. Cross-checks against
    /// the decryptor now go through DecryptSectorAsync/ReadDecryptedAsync (the only way to reach that
    /// data from a test project without InternalsVisibleTo), not the internal sync methods
    /// DecryptedBlockDeviceStream itself uses.
    /// </summary>
    public class DecryptedBlockDeviceStreamTests
    {
        private static async Task<(SectorDecryptor decryptor, DecryptedBlockDeviceStream stream)> CreateStreamAsync()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);
            var decryptor = await SectorDecryptor.CreateAsync(TestContainers.AesNtfs.ContainerFile, header);
            return (decryptor, new DecryptedBlockDeviceStream(decryptor));
        }

        [Fact]
        public void Constructor_NullDecryptor_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new DecryptedBlockDeviceStream(null!));
        }

        [Fact]
        public async Task Capabilities_AreReadSeekOnly()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.True(stream.CanRead);
                Assert.True(stream.CanSeek);
                Assert.False(stream.CanWrite);
            }
        }

        [Fact]
        public async Task Length_MatchesSectorCountTimesSectorSize()
        {
            var (decryptor, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.Equal(decryptor.SectorCount * (long)decryptor.SectorSize, stream.Length);
            }
        }

        [Fact]
        public async Task Position_DefaultsToZero()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.Equal(0, stream.Position);
            }
        }

        [Fact]
        public async Task Position_Setter_MovesToGivenOffset()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                stream.Position = 100;

                Assert.Equal(100, stream.Position);
            }
        }

        [Fact]
        public async Task Seek_FromBegin_SetsAbsolutePosition()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                var result = stream.Seek(200, SeekOrigin.Begin);

                Assert.Equal(200, result);
                Assert.Equal(200, stream.Position);
            }
        }

        [Fact]
        public async Task Seek_FromCurrent_IsRelativeToPosition()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                stream.Position = 100;

                var result = stream.Seek(50, SeekOrigin.Current);

                Assert.Equal(150, result);
                Assert.Equal(150, stream.Position);
            }
        }

        [Fact]
        public async Task Seek_FromEnd_IsRelativeToLength()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                var result = stream.Seek(-10, SeekOrigin.End);

                Assert.Equal(stream.Length - 10, result);
                Assert.Equal(stream.Length - 10, stream.Position);
            }
        }

        [Fact]
        public async Task Seek_ResultingInNegativePosition_ThrowsArgumentException()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.Throws<ArgumentException>(() => stream.Seek(-1, SeekOrigin.Begin));
            }
        }

        [Fact]
        public async Task Seek_PastEndOfStream_IsAllowed()
        {
            // Seeking beyond Length is standard Stream behaviour (matches e.g. FileStream); it is
            // only a subsequent Read at that position that yields zero bytes.
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                var result = stream.Seek(stream.Length + 1000, SeekOrigin.Begin);

                Assert.Equal(stream.Length + 1000, result);
            }
        }

        [Fact]
        public async Task Read_SingleSector_MatchesSectorDecryptorReadDecryptedAsync()
        {
            var (decryptor, stream) = await CreateStreamAsync();
            using (stream)
            {
                var buffer = new byte[decryptor.SectorSize];

                var bytesRead = stream.Read(buffer, 0, buffer.Length);

                Assert.Equal(decryptor.SectorSize, bytesRead);
                Assert.Equal(await decryptor.ReadDecryptedAsync(0, decryptor.SectorSize), buffer);
            }
        }

        [Fact]
        public async Task Read_PartialReadWithinSector_MatchesSectorDecryptorReadDecryptedAsync()
        {
            var (decryptor, stream) = await CreateStreamAsync();
            using (stream)
            {
                stream.Position = 20;
                var buffer = new byte[10];

                var bytesRead = stream.Read(buffer, 0, buffer.Length);

                Assert.Equal(10, bytesRead);
                Assert.Equal(await decryptor.ReadDecryptedAsync(20, 10), buffer);
            }
        }

        [Fact]
        public async Task Read_PartialReadCrossingSectorBoundary_MatchesSectorDecryptorReadDecryptedAsync()
        {
            var (decryptor, stream) = await CreateStreamAsync();
            using (stream)
            {
                stream.Position = decryptor.SectorSize - 5;
                var buffer = new byte[10];

                var bytesRead = stream.Read(buffer, 0, buffer.Length);

                Assert.Equal(10, bytesRead);
                Assert.Equal(await decryptor.ReadDecryptedAsync(decryptor.SectorSize - 5, 10), buffer);
            }
        }

        [Fact]
        public async Task Read_MultiSectorRange_MatchesSectorDecryptorReadDecryptedAsync()
        {
            var (decryptor, stream) = await CreateStreamAsync();
            using (stream)
            {
                var count = 3 * decryptor.SectorSize;
                var buffer = new byte[count];

                var bytesRead = stream.Read(buffer, 0, count);

                Assert.Equal(count, bytesRead);
                Assert.Equal(await decryptor.ReadDecryptedAsync(0, count), buffer);
            }
        }

        [Fact]
        public async Task Read_MultiSectorRange_MatchesManualConcatenationOfDecryptSectorAsyncCalls()
        {
            var (decryptor, stream) = await CreateStreamAsync();
            using (stream)
            {
                var buffer = new byte[3 * decryptor.SectorSize];

                var bytesRead = stream.Read(buffer, 0, buffer.Length);

                Assert.Equal(buffer.Length, bytesRead);
                var expected = (await decryptor.DecryptSectorAsync(0))
                    .Concat(await decryptor.DecryptSectorAsync(1))
                    .Concat(await decryptor.DecryptSectorAsync(2))
                    .ToArray();
                Assert.Equal(expected, buffer);
            }
        }

        [Fact]
        public async Task Read_AdvancesPositionByBytesRead()
        {
            var (decryptor, stream) = await CreateStreamAsync();
            using (stream)
            {
                var buffer = new byte[decryptor.SectorSize + 10];

                var bytesRead = stream.Read(buffer, 0, buffer.Length);

                Assert.Equal(buffer.Length, bytesRead);
                Assert.Equal(buffer.Length, stream.Position);
            }
        }

        [Fact]
        public async Task Read_NearEndOfStream_ReturnsOnlyAvailableBytes()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                stream.Position = stream.Length - 5;
                var buffer = new byte[20];

                var bytesRead = stream.Read(buffer, 0, 20);

                Assert.Equal(5, bytesRead);
                Assert.Equal(stream.Length, stream.Position);
            }
        }

        [Fact]
        public async Task Read_AtEndOfStream_ReturnsZero()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                stream.Position = stream.Length;
                var buffer = new byte[20];

                var bytesRead = stream.Read(buffer, 0, 20);

                Assert.Equal(0, bytesRead);
            }
        }

        [Fact]
        public async Task Read_PastEndOfStream_ReturnsZero()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                stream.Position = stream.Length + 100;
                var buffer = new byte[20];

                var bytesRead = stream.Read(buffer, 0, 20);

                Assert.Equal(0, bytesRead);
            }
        }

        [Fact]
        public async Task Read_ZeroCount_ReturnsZeroAndDoesNotMovePosition()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                stream.Position = 42;
                var buffer = new byte[0];

                var bytesRead = stream.Read(buffer, 0, 0);

                Assert.Equal(0, bytesRead);
                Assert.Equal(42, stream.Position);
            }
        }

        [Fact]
        public async Task Read_NullBuffer_ThrowsArgumentNullException()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.Throws<ArgumentNullException>(() => stream.Read(null!, 0, 10));
            }
        }

        [Fact]
        public async Task Read_NegativeOffset_ThrowsArgumentException()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.Throws<ArgumentException>(() => stream.Read(new byte[10], -1, 5));
            }
        }

        [Fact]
        public async Task Read_NegativeCount_ThrowsArgumentException()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.Throws<ArgumentException>(() => stream.Read(new byte[10], 0, -1));
            }
        }

        [Fact]
        public async Task Read_RangeExceedingBufferLength_ThrowsArgumentException()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.Throws<ArgumentException>(() => stream.Read(new byte[10], 5, 10));
            }
        }

        [Fact]
        public async Task Write_ThrowsNotSupportedException()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
            }
        }

        [Fact]
        public async Task SetLength_ThrowsNotSupportedException()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                Assert.Throws<NotSupportedException>(() => stream.SetLength(100));
            }
        }

        [Fact]
        public async Task Flush_DoesNotThrow()
        {
            var (_, stream) = await CreateStreamAsync();
            using (stream)
            {
                var exception = Record.Exception(() => stream.Flush());

                Assert.Null(exception);
            }
        }

        [Fact]
        public async Task Read_DoesNotAllocateMemoryProportionalToContainerSize()
        {
            // The container is ~5 MB; if Read pre-decrypted (or otherwise touched) the whole
            // container, allocations would be on that order. A single-sector read through the
            // stream should allocate at most a handful of small, sector-sized buffers.
            // DecryptedBlockDeviceStream.Read itself stays fully synchronous on the calling thread
            // (it calls the decryptor's internal sync path, not Task.Run), so
            // GetAllocatedBytesForCurrentThread() still correctly captures its allocations.
            var (decryptor, stream) = await CreateStreamAsync();
            using (stream)
            {
                var warmUpBytesRead = stream.Read(new byte[decryptor.SectorSize], 0, decryptor.SectorSize); // warm up
                Assert.Equal(decryptor.SectorSize, warmUpBytesRead);

                var before = GC.GetAllocatedBytesForCurrentThread();
                stream.Position = 1024;
                var bytesRead = stream.Read(new byte[decryptor.SectorSize], 0, decryptor.SectorSize);
                var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

                Assert.Equal(decryptor.SectorSize, bytesRead);
                Assert.True(allocated < 200_000, $"Expected well under 200,000 bytes allocated, got {allocated}.");
            }
        }
    }
}
