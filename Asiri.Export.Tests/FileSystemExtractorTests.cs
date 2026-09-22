using System;
using System.IO;
using System.Threading.Tasks;
using DiscUtils;
using DiscUtils.Streams;
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
        /// <summary>Opens a previously-exported disk image back up, for a given format, to verify it.</summary>
        private static VirtualDisk OpenDisk(FileSystemExportFormat format, Stream stream)
        {
            stream.Position = 0;
            switch (format)
            {
                case FileSystemExportFormat.Vhd:
                    return new DiscUtils.Vhd.Disk(stream, Ownership.None);
                case FileSystemExportFormat.Vhdx:
                    return new DiscUtils.Vhdx.Disk(stream, Ownership.None);
                case FileSystemExportFormat.Vdi:
                    return new DiscUtils.Vdi.Disk(stream, Ownership.None);
                default:
                    throw new ArgumentException($"No reader configured for format: {format}.", nameof(format));
            }
        }

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
        public async Task ExportAsync_RawImage_RejectsPartitionTableOption()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                using var destination = new MemoryStream();
                await Assert.ThrowsAsync<ArgumentException>(() =>
                    new FileSystemExtractor(container).ExportAsync(destination, FileSystemExportFormat.RawImage, PartitionTableOption.SingleMbrPartition));
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [InlineData(FileSystemExportFormat.Vhd)]
        [InlineData(FileSystemExportFormat.Vhdx)]
        [InlineData(FileSystemExportFormat.Vdi)]
        public async Task ExportAsync_NoPartitionTable_WrapsFileSystemWithMatchingCapacityAndContent(FileSystemExportFormat format)
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                using var raw = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(raw, FileSystemExportFormat.RawImage);

                using var wrapped = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(wrapped, format);

                using var disk = OpenDisk(format, wrapped);

                // Some formats (VHDX) round capacity up to their own alignment requirement (see
                // FileSystemExtractor.GetMinimumCapacityAlignment) - the filesystem still occupies
                // exactly its own size at the start, but the disk itself may be padded slightly
                // larger.
                Assert.True(disk.Capacity >= raw.Length);

                using var content = new MemoryStream();
                disk.Content.CopyTo(content);
                Assert.Equal(raw.ToArray(), content.ToArray()[..(int)raw.Length]);
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [InlineData(FileSystemExportFormat.Vhd)]
        [InlineData(FileSystemExportFormat.Vhdx)]
        [InlineData(FileSystemExportFormat.Vdi)]
        public async Task ExportAsync_SingleMbrPartition_WrapsFileSystemInASinglePartitionMatchingContent(FileSystemExportFormat format)
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                using var raw = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(raw, FileSystemExportFormat.RawImage);

                using var wrapped = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(wrapped, format, PartitionTableOption.SingleMbrPartition);

                using var disk = OpenDisk(format, wrapped);

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
