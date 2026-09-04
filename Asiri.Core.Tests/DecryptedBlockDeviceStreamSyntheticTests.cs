using System;
using System.Diagnostics;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for <see cref="DecryptedBlockDeviceStream"/> that build a synthetic container (via
    /// Stage 2's <see cref="SyntheticContainerHelper"/>) to prove that reading through the stream -
    /// not just through SectorDecryptor directly - never pre-decrypts the container, over a
    /// container far larger than would be practical to fully decrypt eagerly.
    /// </summary>
    public class DecryptedBlockDeviceStreamSyntheticTests
    {
        [Fact]
        public async Task Seek_And_Read_OnMultiGigabyteSparseContainer_CompletesQuickly()
        {
            const long masterKeyScopeOffset = 65536;
            const int sectorSize = 512;
            const long fileLength = 4L * 1024 * 1024 * 1024; // 4 GB
            const long encryptedAreaSize = fileLength - masterKeyScopeOffset;
            const long targetSectorIndex = 3_000_000; // deep inside the 4 GB file

            using var container = SyntheticContainerHelper.CreateContainer(
                fileLength, sectorSize, masterKeyScopeOffset, encryptedAreaSize, seed: 40);

            var plaintext = MakePattern(512, 0x5A);
            SyntheticContainerHelper.WriteEncryptedData(
                container, masterKeyScopeOffset + targetSectorIndex * sectorSize, plaintext);

            var header = await HeaderParser.ParseAsync(container.Path, container.Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);
            var decryptor = await SectorDecryptor.CreateAsync(container.Path, header);
            using var stream = new DecryptedBlockDeviceStream(decryptor);

            Assert.Equal(encryptedAreaSize, stream.Length);

            var stopwatch = Stopwatch.StartNew();
            stream.Position = targetSectorIndex * sectorSize;
            var buffer = new byte[sectorSize];
            var bytesRead = stream.Read(buffer, 0, sectorSize);
            stopwatch.Stop();

            Assert.Equal(sectorSize, bytesRead);
            Assert.Equal(plaintext, buffer);
            Assert.True(stopwatch.ElapsedMilliseconds < 5000,
                $"Expected a single-sector stream read from a 4 GB container to complete in well under 5 seconds, took {stopwatch.ElapsedMilliseconds} ms.");
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
