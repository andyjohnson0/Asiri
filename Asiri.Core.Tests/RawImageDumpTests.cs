using System.IO;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;
using Xunit;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for VeraCryptContainer.ExportFileSystemAsync - a diagnostic escape hatch that writes a
    /// container's decrypted filesystem straight to a stream, with none of
    /// Asiri's own DiscUtils-based interpretation of it in the way, so the plaintext can be handed to
    /// a real filesystem-checking tool or another reviewer entirely outside Asiri. Runs against a real
    /// VeraCrypt-created fixture, not a container this suite creates itself - the point of this
    /// feature is to let something OTHER than Asiri's own read path judge the bytes, so proving it
    /// works against a container Asiri didn't format itself is the more meaningful check.
    /// </summary>
    [Trait("Category", "Integration")]
    public class RawImageDumpTests
    {
        [Fact]
        public async Task ExportFileSystemAsync_FullImage_WritesExactlyFileSystemSizeBytes()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                using var destination = new MemoryStream();
                await container.ExportFileSystemAsync(destination);

                // 262144 = HeaderParser.TotalHeaderOverheadSize (internal - re-stated here rather
                // than referenced, matching this project's convention of not granting
                // InternalsVisibleTo to the test assembly; ChangePasswordTests and
                // CreateContainerTests do the same).
                Assert.Equal(fixture.ContainerFile.Length - 262144, destination.Length);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ExportFileSystemAsync_RawImageBootSectorOnly_Writes512Bytes()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                using var destination = new MemoryStream();
                await container.ExportFileSystemAsync(destination, FileSystemExportFormat.RawImageBootSectorOnly);

                Assert.Equal(512, destination.Length);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ExportFileSystemAsync_RawImageBootSectorOnly_MatchesStartOfFullImage()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                using var full = new MemoryStream();
                await container.ExportFileSystemAsync(full);

                using var bootOnly = new MemoryStream();
                await container.ExportFileSystemAsync(bootOnly, FileSystemExportFormat.RawImageBootSectorOnly);

                Assert.Equal(full.ToArray()[..512], bootOnly.ToArray());
            }
            finally
            {
                container.Close();
            }
        }
    }
}
