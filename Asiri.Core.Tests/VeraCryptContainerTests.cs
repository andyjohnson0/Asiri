using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for the filesystem-agnostic contract of <see cref="VeraCryptContainer.OpenAsync"/> and
    /// <see cref="VeraCryptContainer.Close"/> - argument validation and closed-container lifetime
    /// behaviour that should hold regardless of which filesystem type a container uses. Tests that
    /// exercise a real container's Open/Close lifecycle run against every fixture in
    /// <see cref="TestContainers"/> via [Theory]/[MemberData], since this behaviour is implemented
    /// once, generically, and should not vary by filesystem backend; the few tests that only
    /// validate an argument (null checks, unsupported enum values, a missing file, a wrong password)
    /// use a single representative fixture, since the fixture choice is incidental to what they test.
    /// Assertions about a specific container's actual content live in ContainerContentTests.cs and
    /// under Filesystem/Ntfs and Filesystem/Fat instead.
    ///
    /// OpenAsync's synchronous argument guards (null path/password, unsupported enum values) throw
    /// immediately, before any Task is returned - confirmed empirically. The file-not-found and
    /// wrong-password checks, by contrast, live one level deeper (inside HeaderParser.ParseAsync,
    /// invoked from within an async method), so C# defers those exceptions onto the returned Task
    /// regardless of how "synchronous" the check itself looks. This inconsistency is a known,
    /// deliberately-deferred refinement, not a bug. All tests below use Assert.ThrowsAsync uniformly
    /// regardless of which case applies, rather than asserting the immediate/deferred distinction
    /// itself: xUnit's analyzer actively forbids Assert.Throws on any call that returns a Task (to
    /// catch the far more common mistake of forgetting to await a genuinely async exception), and
    /// ThrowsAsync correctly catches an exception whether it was already on the Task when returned or
    /// only surfaced later - it doesn't need to know which happened.
    /// </summary>
    public class VeraCryptContainerTests
    {
        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task OpenAsync_WithCorrectPassword_ReturnsContainerWithUsableRoot(TestContainers.ContainerFixture fixture)
        {
            // Only checks that a successfully-opened container has a non-null, enumerable Root -
            // not what it actually contains, which is filesystem-specific and covered separately.
            var container = await fixture.OpenAsync();
            try
            {
                Assert.NotNull(container.Root);
                var entries = (await container.Root.GetEntriesAsync()).ToList();
                Assert.NotEmpty(entries);
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task OpenAsync_WithCorrectPassword_SetsAlgorithmAndHashAlgorithmOnContainer(TestContainers.ContainerFixture fixture)
        {
            // Algorithm and HashAlgorithm are given directly by the caller on this (explicit-
            // parameters) overload, but were previously never actually asserted back on the returned
            // container - this closes that gap for both properties in one pass.
            var container = await fixture.OpenAsync();
            try
            {
                Assert.Equal(fixture.Algorithm, container.Algorithm);
                Assert.Equal(fixture.HashAlgorithm, container.HashAlgorithm);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task OpenAsync_NullPath_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                VeraCryptContainer.OpenAsync(null!, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, TestContainers.AesNtfs.FilesystemType));
        }

        [Fact]
        public async Task OpenAsync_NullPassword_ThrowsArgumentNullException()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                VeraCryptContainer.OpenAsync(TestContainers.AesNtfs.ContainerFile, null!, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, TestContainers.AesNtfs.FilesystemType));
        }

        [Fact]
        public async Task OpenAsync_UnsupportedAlgorithm_ThrowsArgumentException()
        {
            await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.OpenAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, (CryptoAlgorithm)99, TestContainers.AesNtfs.HashAlgorithm, TestContainers.AesNtfs.FilesystemType));
        }

        [Fact]
        public async Task OpenAsync_UnsupportedHashAlgorithm_ThrowsArgumentException()
        {
            await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.OpenAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, (HashAlgorithm)99, TestContainers.AesNtfs.FilesystemType));
        }

        [Fact]
        public async Task OpenAsync_UnsupportedFileSystemType_ThrowsArgumentException()
        {
            await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.OpenAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, (FileSystemType)99));
        }

        [Fact]
        public async Task OpenAsync_NonExistentFile_ThrowsArgumentException()
        {
            var missing = new FileInfo(Path.Combine(TestContainers.AesNtfs.ContainerFile.DirectoryName!, "does-not-exist.hc"));

            await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.OpenAsync(missing, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, TestContainers.AesNtfs.FilesystemType));
        }

        [Fact]
        public async Task OpenAsync_WrongPassword_ThrowsInvalidOperationException()
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(TestContainers.AesNtfs.ContainerFile, "definitely-wrong-password", TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm, TestContainers.AesNtfs.FilesystemType));
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Close_AfterSuccessfulOpen_DoesNotThrow(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();

            var exception = Record.Exception(() => container.Close());

            Assert.Null(exception);
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Close_CalledTwice_DoesNotThrow(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            container.Close();

            var exception = Record.Exception(() => container.Close());

            Assert.Null(exception);
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task OpenAsync_CalledTwiceOnSameFile_ProducesIndependentContainers(TestContainers.ContainerFixture fixture)
        {
            var containerA = await fixture.OpenAsync();
            var containerB = await fixture.OpenAsync();

            containerA.Close();

            // Closing A must not affect B's ability to use its own, independently-opened resources.
            var namesFromB = (await containerB.Root.GetEntriesAsync()).Select(e => e.Name).ToList();
            Assert.NotEmpty(namesFromB);

            containerB.Close();
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Root_AccessedAfterClose_ThrowsObjectDisposedException(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            container.Close();

            await Assert.ThrowsAsync<ObjectDisposedException>(() => container.Root.GetEntriesAsync());
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task RootDirectory_ObtainedBeforeClose_ThrowsObjectDisposedExceptionWhenUsedAfterClose(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            var root = container.Root; // obtained while the container is still open

            container.Close();

            await Assert.ThrowsAsync<ObjectDisposedException>(() => root.GetEntriesAsync());
            await Assert.ThrowsAsync<ObjectDisposedException>(() => root.GetFileAsync("test.txt"));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => root.GetDirectoryAsync("data"));
            Assert.Throws<ObjectDisposedException>(() => root.Name);
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Subdirectory_ObtainedBeforeClose_ThrowsObjectDisposedExceptionWhenUsedAfterClose(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            var dataDir = await container.Root.GetDirectoryAsync("data"); // obtained while the container is still open

            container.Close();

            await Assert.ThrowsAsync<ObjectDisposedException>(() => dataDir.GetEntriesAsync());
            await Assert.ThrowsAsync<ObjectDisposedException>(() => dataDir.GetFileAsync("subtest.txt"));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => dataDir.GetDirectoryAsync("nonexistent"));
            Assert.Throws<ObjectDisposedException>(() => dataDir.Name);
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task File_ObtainedBeforeClose_ThrowsObjectDisposedExceptionWhenUsedAfterClose(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            var testTxt = await container.Root.GetFileAsync("test.txt"); // obtained while the container is still open

            container.Close();

            await Assert.ThrowsAsync<ObjectDisposedException>(() => testTxt.ReadAllBytesAsync());
            await Assert.ThrowsAsync<ObjectDisposedException>(() => testTxt.ReadAllTextAsync());
            await Assert.ThrowsAsync<ObjectDisposedException>(() => testTxt.GetLengthAsync());
            Assert.Throws<ObjectDisposedException>(() => testTxt.Name);
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task FileSystemEntry_ObtainedViaGetEntriesBeforeClose_ThrowsObjectDisposedExceptionWhenUsedAfterClose(TestContainers.ContainerFixture fixture)
        {
            // GetEntriesAsync() itself is called - and its underlying directory-listing calls to
            // DiscUtils run - before Close(). This confirms that pre-fetching the list of entries
            // doesn't let a caller bypass the closed check when they subsequently use one of them.
            var container = await fixture.OpenAsync();
            var entries = (await container.Root.GetEntriesAsync()).ToList();

            container.Close();

            Assert.Throws<ObjectDisposedException>(() => entries.Select(e => e.Name).ToList());
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task ObjectDisposedException_AfterClose_IsAlsoAnInvalidOperationException(TestContainers.ContainerFixture fixture)
        {
            // ObjectDisposedException derives from InvalidOperationException, so callers following
            // this project's general "throw only InvalidOperationException/ArgumentException/
            // ArgumentNullException" convention can still catch it by the base type. Assert.Throws<T>
            // requires an exact type match, so this checks the exception's runtime type directly.
            var container = await fixture.OpenAsync();
            container.Close();

            var exception = await Record.ExceptionAsync(() => container.Root.GetEntriesAsync());

            Assert.IsAssignableFrom<InvalidOperationException>(exception);
        }
    }
}
