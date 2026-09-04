using System;
using System.Threading;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Confirms cancellation is honoured, using pre-cancelled tokens, at three representative points
    /// in the async call tree rather than at every one of the ~15 async methods across the library:
    /// <see cref="VeraCryptContainer.OpenAsync"/> (the top-level entry point), <see cref="IFile.ReadAllBytesAsync"/>
    /// (a leaf method reached through the IDirectory/IFile abstraction), and <see cref="SectorDecryptor"/>
    /// directly (where the persistent-FileStream/locking change lives).
    ///
    /// Genuine mid-flight cancellation (cancelling while work is actually in progress, rather than
    /// before it starts) is deliberately not tested: the code path is identical either way -
    /// ThrowIfCancellationRequested() doesn't distinguish "cancelled a nanosecond ago" from
    /// "cancelled a minute ago" - so a timing-dependent test would only add flakiness for no
    /// additional coverage.
    /// </summary>
    public class AsyncCancellationTests
    {
        [Fact]
        public async Task OpenAsync_PreCancelledToken_ThrowsOperationCanceledException()
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                VeraCryptContainer.OpenAsync(
                    TestContainers.AesNtfs.ContainerFile,
                    TestContainers.AesNtfs.Password,
                    TestContainers.AesNtfs.Algorithm,
                    TestContainers.AesNtfs.HashAlgorithm,
                    TestContainers.AesNtfs.FilesystemType,
                    cts.Token));
        }

        [Fact]
        public async Task ReadAllBytesAsync_PreCancelledToken_ThrowsOperationCanceledException()
        {
            var container = await TestContainers.AesNtfs.OpenAsync();
            try
            {
                var file = await container.Root.GetFileAsync("test.txt");

                using var cts = new CancellationTokenSource();
                cts.Cancel();

                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => file.ReadAllBytesAsync(cts.Token));
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task SectorDecryptor_DecryptSectorAsync_PreCancelledToken_ThrowsOperationCanceledException()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);
            using var decryptor = await SectorDecryptor.CreateAsync(TestContainers.AesNtfs.ContainerFile, header);

            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => decryptor.DecryptSectorAsync(0, cts.Token));
        }
    }
}
