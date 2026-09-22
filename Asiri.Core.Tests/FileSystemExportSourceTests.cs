using System;
using System.IO;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;
using Xunit;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for VeraCryptContainer's explicit IFileSystemExportSource implementation - the minimal
    /// surface Asiri.Export's FileSystemExtractor consumes to build real disk-container exports,
    /// without Asiri.Core itself taking a dependency on DiscUtils' virtual-disk packages. Exercised
    /// directly here, independent of Asiri.Export, since that's a separate project this one doesn't
    /// reference.
    /// </summary>
    [Trait("Category", "Integration")]
    public class FileSystemExportSourceTests
    {
        [Fact]
        public async Task Length_MatchesDecryptedFileSystemSize()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                IFileSystemExportSource source = container;

                // 262144 = HeaderParser.TotalHeaderOverheadSize (internal - re-stated here rather
                // than referenced, matching this project's convention of not granting
                // InternalsVisibleTo to the test assembly; ChangePasswordTests and
                // CreateContainerTests do the same).
                Assert.Equal(fixture.ContainerFile.Length - 262144, source.Length);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task FileSystemType_MatchesContainersOwnProperty()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                IFileSystemExportSource source = container;

                Assert.Equal(container.FileSystemType, source.FileSystemType);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task CopyBytesAsync_WritesExactlyRequestedByteCount()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                IFileSystemExportSource source = container;

                using var destination = new MemoryStream();
                await source.CopyBytesAsync(destination, 512, default);

                Assert.Equal(512, destination.Length);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task CopyBytesAsync_PartialCopyMatchesStartOfFullCopy()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            try
            {
                IFileSystemExportSource source = container;

                using var full = new MemoryStream();
                await source.CopyBytesAsync(full, source.Length, default);

                using var partial = new MemoryStream();
                await source.CopyBytesAsync(partial, 512, default);

                Assert.Equal(full.ToArray()[..512], partial.ToArray());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task CopyBytesAsync_ThrowsAfterContainerClosed()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await fixture.OpenAsync();
            IFileSystemExportSource source = container;
            container.Close();

            using var destination = new MemoryStream();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => source.CopyBytesAsync(destination, 512, default));
        }
    }
}
