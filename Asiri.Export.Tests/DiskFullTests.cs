using System;
using System.IO;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;
using uk.andyjohnson.Asiri.Core.Tests;

namespace uk.andyjohnson.Asiri.Export.Tests
{
    /// <summary>
    /// Exploratory tests answering a specific question: does export handle a destination that runs
    /// out of space partway through, gracefully - i.e. does a clear exception propagate (rather than
    /// being swallowed, or masked by a second exception during cleanup), and is the source container
    /// left in a usable state afterward? Uses DiskFullSimulatingStream rather than an actual full
    /// disk, since the latter isn't practical to set up deterministically in a test.
    /// </summary>
    [Trait("Category", "Integration")]
    public class DiskFullTests
    {
        [Fact]
        public async Task ExportAsync_RawImage_DestinationRunsOutOfSpace_ThrowsAndReportsWhatHappened()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                var tooSmall = new DiskFullSimulatingStream(writeLimit: 4096);

                var ex = await Record.ExceptionAsync(() =>
                    new FileSystemExtractor(container).ExportAsync(tooSmall, FileSystemExportFormat.RawImage));

                Assert.NotNull(ex);
                Console.WriteLine($"RawImage: {ex!.GetType().FullName}: {ex.Message}");
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [InlineData(FileSystemExportFormat.Vhd, PartitionTableOption.None)]
        [InlineData(FileSystemExportFormat.Vhd, PartitionTableOption.SingleMbrPartition)]
        [InlineData(FileSystemExportFormat.Vhdx, PartitionTableOption.None)]
        [InlineData(FileSystemExportFormat.Vhdx, PartitionTableOption.SingleMbrPartition)]
        [InlineData(FileSystemExportFormat.Vdi, PartitionTableOption.None)]
        [InlineData(FileSystemExportFormat.Vdi, PartitionTableOption.SingleMbrPartition)]
        public async Task ExportAsync_DestinationRunsOutOfSpace_ThrowsAndReportsWhatHappened(FileSystemExportFormat format, PartitionTableOption partitionTable)
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                var tooSmall = new DiskFullSimulatingStream(writeLimit: 4096);

                var ex = await Record.ExceptionAsync(() =>
                    new FileSystemExtractor(container).ExportAsync(tooSmall, format, partitionTable));

                Assert.NotNull(ex);
                Console.WriteLine($"{format}/{partitionTable}: {ex!.GetType().FullName}: {ex.Message}");
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ExportAsync_AfterFailedExport_ContainerIsStillUsable()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                var tooSmall = new DiskFullSimulatingStream(writeLimit: 4096);
                await Record.ExceptionAsync(() =>
                    new FileSystemExtractor(container).ExportAsync(tooSmall, FileSystemExportFormat.RawImage));

                // The container itself must still be usable after a failed export - a subsequent
                // export with enough room should succeed and match what an export against a
                // never-failed container produces.
                using var retry = new MemoryStream();
                await new FileSystemExtractor(container).ExportAsync(retry, FileSystemExportFormat.RawImage);

                Assert.Equal(((IFileSystemExportSource)container).Length, retry.Length);
            }
            finally
            {
                container.Close();
            }
        }
    }
}
