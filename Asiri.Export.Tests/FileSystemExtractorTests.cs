using System.IO;
using System.Threading.Tasks;
using DiscUtils.Vhd;
using uk.andyjohnson.Asiri.Core;
using uk.andyjohnson.Asiri.Core.Tests;

namespace uk.andyjohnson.Asiri.Export.Tests
{
    /// <summary>
    /// Tests for FileSystemExtractor - built against a real VeraCrypt-created fixture (via
    /// Asiri.Core.Tests' own TestContainers catalogue), not a container this suite creates itself,
    /// matching this project's established convention of proving export against something Asiri
    /// didn't format itself. Runs against a real, already-mounted-equivalent decrypted filesystem
    /// through VeraCryptContainer's IFileSystemExportSource implementation.
    /// </summary>
    [Trait("Category", "Integration")]
    public class FileSystemExtractorTests
    {
        [Fact]
        public async Task ExportAsync_RawImage_WritesExactlyFileSystemSizeBytes()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                using var destination = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(destination);

                Assert.Equal(((IFileSystemExportSource)container).Length, destination.Length);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ExportAsync_Vhd_WrapsFileSystemWithMatchingCapacityAndContent()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                using var raw = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(raw, FileSystemExportFormat.RawImage);

                using var vhdStream = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(vhdStream, FileSystemExportFormat.Vhd);

                vhdStream.Position = 0;
                using var disk = new Disk(vhdStream, DiscUtils.Streams.Ownership.None);

                Assert.Equal(raw.Length, disk.Capacity);

                using var content = new MemoryStream();
                disk.Content.CopyTo(content);
                Assert.Equal(raw.ToArray(), content.ToArray());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ExportAsync_VhdWithPartitionTable_WrapsFileSystemInASinglePartitionMatchingContent()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                using var raw = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(raw, FileSystemExportFormat.RawImage);

                using var vhdStream = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(vhdStream, FileSystemExportFormat.VhdWithPartitionTable);

                vhdStream.Position = 0;
                using var disk = new Disk(vhdStream, DiscUtils.Streams.Ownership.None);

                Assert.Single(disk.Partitions!.Partitions);

                using var content = new MemoryStream();
                using (var partitionStream = disk.Partitions[0].Open())
                {
                    partitionStream.CopyTo(content);
                }

                // The partition itself is aligned to a cylinder boundary by BiosPartitionTable, so
                // it's typically larger than the filesystem - the filesystem occupies its start, not
                // necessarily all of it.
                Assert.True(content.Length >= raw.Length);
                Assert.Equal(raw.ToArray(), content.ToArray()[..(int)raw.Length]);
            }
            finally
            {
                container.Close();
            }
        }
    }
}
