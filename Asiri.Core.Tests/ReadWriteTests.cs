using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for read-write access (issue #3), parameterized across every filesystem type that now
    /// has real write support - NTFS, FAT16, FAT32, and exFAT (see <see cref="WritableFixtures"/>) -
    /// since every test here calls only through the filesystem-agnostic IFile/IDirectory/
    /// VeraCryptContainer surface, never anything NTFS/FAT/exFAT-specific. Running the same test
    /// against all four is deliberate, not just thoroughness for its own sake: FAT and exFAT support
    /// is new in this stage, and each has its own real behavioural differences from NTFS (e.g. 8.3
    /// naming, case handling) that only actually exercising them - not just NTFS - would catch.
    ///
    /// The ContainerAccessMode/IsWritable gating tests near the top are the exception: that logic is
    /// entirely filesystem-agnostic (it never reaches DiscUtils at all), so those run once, against
    /// NTFS only, rather than being parameterized for no added value.
    ///
    /// Every test that actually writes opens a TemporaryContainerCopy of the real fixture - never the
    /// checked-in original under "Test Data".
    /// </summary>
    [Trait("Category", "Integration")]
    public class ReadWriteTests
    {
        public static IEnumerable<object[]> WritableFixtures()
        {
            yield return new object[] { TestContainers.AesNtfs };
            yield return new object[] { TestContainers.AesFat16 };
            yield return new object[] { TestContainers.AesFat32 };
            yield return new object[] { TestContainers.AesExFat };
        }

        private static async Task<(TemporaryContainerCopy copy, VeraCryptContainer container)> OpenWritableCopyAsync(
            TestContainers.ContainerFixture fixture, bool armWriting = true)
        {
            var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            var container = await VeraCryptContainer.OpenAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType,
                accessMode: ContainerAccessMode.ReadWrite);
            if (armWriting)
            {
                container.IsWritable = true;
            }
            return (copy, container);
        }

        // --- ContainerAccessMode / IsWritable gating (filesystem-agnostic - tested once, via NTFS) ---

        [Fact]
        public async Task OpenAsync_DefaultAccessMode_IsWritableStartsFalseAndCannotBeEnabled()
        {
            var fixture = TestContainers.AesNtfs;
            var container = await VeraCryptContainer.OpenAsync(
                fixture.ContainerFile, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType);
            try
            {
                Assert.False(container.IsWritable);
                Assert.Throws<InvalidOperationException>(() => container.IsWritable = true);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task OpenAsync_ReadWriteAccessMode_IsWritableStartsFalse()
        {
            var (copy, container) = await OpenWritableCopyAsync(TestContainers.AesNtfs, armWriting: false);
            using (copy)
            {
                try
                {
                    // Opening for write access and actually permitting a write are deliberately two
                    // separate, both-required steps - see ContainerLifetime's own remarks.
                    Assert.False(container.IsWritable);
                }
                finally
                {
                    container.Close();
                }
            }
        }

        // --- Close() concurrency: must not race an in-flight operation ---

        [Fact]
        public async Task Close_WaitsForAnyInFlightOperation_RatherThanRacingIt()
        {
            // Regression test for a real bug: Close() used to dispose the underlying filesystem and
            // stream without taking ContainerLifetime.Lock - the same lock every read/write call
            // takes, but only around its own DiscUtils call, not its whole async lifetime. If a
            // write's DiscUtils call was still in flight (holding that lock) when Close() ran
            // concurrently on another thread, Close() could tear the stream down mid-write - not
            // merely throw, but leave a multi-step on-disk update (an index or MFT change spanning
            // more than one write) partially applied, corrupting the volume. This was discovered from
            // a real container, emptied of its entire root directory listing, after moving a file in
            // the WPF browser app and closing shortly afterward.
            //
            // The race can't be reproduced reliably by timing real I/O against real DiscUtils calls -
            // both are far too fast against these small test fixtures to reliably land inside the
            // tiny window a flaky, timing-based test would need. Instead, this simulates "an
            // operation is in flight" directly: it takes the same internal lock (via reflection -
            // there is no public way to observe this synchronization contract) that a real operation
            // would hold only around its own DiscUtils call, and asserts that a concurrent Close()
            // call blocks until that lock is released, rather than proceeding regardless.
            var (copy, container) = await OpenWritableCopyAsync(TestContainers.AesNtfs);
            using (copy)
            {
                try
                {
                    var lifetimeField = typeof(VeraCryptContainer).GetField("_lifetime", BindingFlags.NonPublic | BindingFlags.Instance);
                    Assert.NotNull(lifetimeField);
                    var lifetime = lifetimeField!.GetValue(container);
                    Assert.NotNull(lifetime);
                    var lockProperty = lifetime!.GetType().GetProperty("Lock", BindingFlags.Public | BindingFlags.Instance);
                    Assert.NotNull(lockProperty);
                    var lockObject = lockProperty!.GetValue(lifetime);
                    Assert.NotNull(lockObject);

                    var closeStarted = new ManualResetEventSlim(false);
                    var closeCompleted = new ManualResetEventSlim(false);

                    lock (lockObject!)
                    {
                        _ = Task.Run(() =>
                        {
                            closeStarted.Set();
                            container.Close();
                            closeCompleted.Set();
                        });

                        Assert.True(closeStarted.Wait(TimeSpan.FromSeconds(5)), "Close() never started on its own thread.");
                        Assert.False(closeCompleted.Wait(TimeSpan.FromMilliseconds(300)),
                            "Close() completed while the lock representing an in-flight operation was still held - " +
                            "it isn't synchronizing with in-flight operations.");
                    }

                    // Lock released - Close() should now be free to proceed and complete.
                    Assert.True(closeCompleted.Wait(TimeSpan.FromSeconds(5)), "Close() did not complete after the lock was released.");
                }
                finally
                {
                    container.Close();
                }
            }
        }

        // --- These gate on IsWritable before ever reaching DiscUtils, so they're worth running
        // across all four fixtures too, cheaply proving the gate itself doesn't depend on filesystem
        // type despite living inside each filesystem's own wrapper classes.

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task CreateFileAsync_WhenIsWritableFalse_ThrowsInvalidOperationException_EvenThoughOpenedReadWrite(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture, armWriting: false);
            using (copy)
            {
                try
                {
                    await Assert.ThrowsAsync<InvalidOperationException>(() => container.Root.CreateFileAsync("new.txt"));
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task CreateFileAsync_AfterDisablingIsWritableAgain_ThrowsInvalidOperationException(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    container.IsWritable = false;
                    await Assert.ThrowsAsync<InvalidOperationException>(() => container.Root.CreateFileAsync("new.txt"));
                }
                finally
                {
                    container.Close();
                }
            }
        }

        // --- Create ---

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task CreateFileAsync_Empty_CreatesZeroLengthFile(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var file = await container.Root.CreateFileAsync("new.txt");

                    Assert.Equal(0, await file.GetLengthAsync());
                    var reopened = await container.Root.GetFileAsync("new.txt");
                    Assert.Equal(0, await reopened.GetLengthAsync());
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task CreateFileAsync_FromStream_WritesGivenContent(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    using var content = new MemoryStream(Encoding.UTF8.GetBytes("Hello from a stream."));
                    var file = await container.Root.CreateFileAsync("stream.txt", content);

                    Assert.Equal("Hello from a stream.", await file.ReadAllTextAsync());
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task CreateFileAsync_NameAlreadyExists_Throws(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    // test.txt already exists in every fixture (see the Verification Checklist in
                    // Asiri.Core.Tests/AGENT.md) - CreateFileAsync creates a new file, it must not
                    // silently overwrite an existing one.
                    await Assert.ThrowsAnyAsync<Exception>(() => container.Root.CreateFileAsync("test.txt"));
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task CreateDirectoryAsync_CreatesNewSubdirectory(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var dir = await container.Root.CreateDirectoryAsync("newdir");
                    var file = await dir.CreateFileAsync("inside.txt");

                    var reopenedDir = await container.Root.GetDirectoryAsync("newdir");
                    var reopenedFile = await reopenedDir.GetFileAsync("inside.txt");
                    Assert.Equal("\\newdir\\inside.txt", reopenedFile.Path);
                }
                finally
                {
                    container.Close();
                }
            }
        }

        // --- Delete ---

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task DeleteAsync_File_RemovesIt(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var file = await container.Root.CreateFileAsync("toDelete.txt");
                    await file.DeleteAsync();

                    await Assert.ThrowsAsync<InvalidOperationException>(() => container.Root.GetFileAsync("toDelete.txt"));
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task DeleteAsync_EmptyDirectory_RemovesIt(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var dir = await container.Root.CreateDirectoryAsync("emptyDir");
                    await dir.DeleteAsync();

                    await Assert.ThrowsAsync<InvalidOperationException>(() => container.Root.GetDirectoryAsync("emptyDir"));
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task DeleteAsync_NonEmptyDirectory_WithoutRecursive_Throws(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var dir = await container.Root.CreateDirectoryAsync("nonEmptyDir");
                    await dir.CreateFileAsync("inside.txt");

                    await Assert.ThrowsAnyAsync<Exception>(() => dir.DeleteAsync());
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task DeleteAsync_NonEmptyDirectory_WithRecursive_RemovesItAndContents(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var dir = await container.Root.CreateDirectoryAsync("recursiveDir");
                    await dir.CreateFileAsync("inside.txt");

                    await dir.DeleteAsync(recursive: true);

                    await Assert.ThrowsAsync<InvalidOperationException>(() => container.Root.GetDirectoryAsync("recursiveDir"));
                }
                finally
                {
                    container.Close();
                }
            }
        }

        // --- Rename / Move ---

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task RenameAsync_File_UpdatesNameAndPathInPlace(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var file = await container.Root.CreateFileAsync("original.txt");

                    await file.RenameAsync("renamed.txt");

                    Assert.Equal("renamed.txt", file.Name);
                    Assert.Equal("\\renamed.txt", file.Path);
                    var reopened = await container.Root.GetFileAsync("renamed.txt");
                    Assert.NotNull(reopened);
                    await Assert.ThrowsAsync<InvalidOperationException>(() => container.Root.GetFileAsync("original.txt"));
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task RenameAsync_Directory_UpdatesNameAndPathInPlace(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var dir = await container.Root.CreateDirectoryAsync("originalDir");

                    await dir.RenameAsync("renamedDir");

                    Assert.Equal("renamedDir", dir.Name);
                    Assert.Equal("\\renamedDir", dir.Path);
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task MoveToAsync_File_MovesToNewParentKeepingName(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var destination = await container.Root.CreateDirectoryAsync("destDir");
                    var file = await container.Root.CreateFileAsync("toMove.txt");

                    await file.MoveToAsync(destination);

                    Assert.Equal("\\destDir\\toMove.txt", file.Path);
                    var reopened = await destination.GetFileAsync("toMove.txt");
                    Assert.NotNull(reopened);
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task MoveToAsync_Directory_MovesToNewParentKeepingName(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var destination = await container.Root.CreateDirectoryAsync("destDir2");
                    var dirToMove = await container.Root.CreateDirectoryAsync("toMoveDir");

                    await dirToMove.MoveToAsync(destination);

                    Assert.Equal("\\destDir2\\toMoveDir", dirToMove.Path);
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task MoveToAsync_File_DestinationFromDifferentContainer_ThrowsArgumentException(TestContainers.ContainerFixture fixture)
        {
            // Two different directory wrapper instances backed by two entirely unrelated
            // container/filesystem instances (rather than two directories within the same
            // container) - a check that only verified "is this the right wrapper type" would pass
            // this just as happily as a real destination, since both containers produce that type.
            var (copyA, containerA) = await OpenWritableCopyAsync(fixture);
            var (copyB, containerB) = await OpenWritableCopyAsync(fixture);
            using (copyA)
            using (copyB)
            {
                try
                {
                    var file = await containerA.Root.CreateFileAsync("toMove.txt");

                    await Assert.ThrowsAsync<ArgumentException>(() => file.MoveToAsync(containerB.Root));
                }
                finally
                {
                    containerA.Close();
                    containerB.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task MoveToAsync_Directory_DestinationFromDifferentContainer_ThrowsArgumentException(TestContainers.ContainerFixture fixture)
        {
            var (copyA, containerA) = await OpenWritableCopyAsync(fixture);
            var (copyB, containerB) = await OpenWritableCopyAsync(fixture);
            using (copyA)
            using (copyB)
            {
                try
                {
                    var dirToMove = await containerA.Root.CreateDirectoryAsync("toMoveDir");

                    await Assert.ThrowsAsync<ArgumentException>(() => dirToMove.MoveToAsync(containerB.Root));
                }
                finally
                {
                    containerA.Close();
                    containerB.Close();
                }
            }
        }

        // --- Attributes / timestamps ---

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task SetAttributesAsync_SetsAttributes(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var file = await container.Root.CreateFileAsync("attrs.txt");

                    await file.SetAttributesAsync(FileAttributes.ReadOnly | FileAttributes.Hidden);

                    var attrs = await file.GetAttributesAsync();
                    Assert.True((attrs & FileAttributes.ReadOnly) != 0);
                    Assert.True((attrs & FileAttributes.Hidden) != 0);
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task SetCreationTimeUtcAsync_SetsCreationTime(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var file = await container.Root.CreateFileAsync("time.txt");
                    var expected = new DateTime(2020, 6, 15, 12, 0, 0, DateTimeKind.Utc);

                    await file.SetCreationTimeUtcAsync(expected);

                    Assert.Equal(expected, await file.GetCreationTimeUtcAsync());
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task SetLastWriteTimeUtcAsync_SetsLastWriteTime(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var file = await container.Root.CreateFileAsync("time2.txt");
                    var expected = new DateTime(2021, 3, 4, 8, 30, 0, DateTimeKind.Utc);

                    await file.SetLastWriteTimeUtcAsync(expected);

                    Assert.Equal(expected, await file.GetLastWriteTimeUtcAsync());
                }
                finally
                {
                    container.Close();
                }
            }
        }

        // --- OpenWriteAsync, and persistence across a full close/reopen cycle ---

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task OpenWriteAsync_TruncatesAndWritesNewContent(TestContainers.ContainerFixture fixture)
        {
            var (copy, container) = await OpenWritableCopyAsync(fixture);
            using (copy)
            {
                try
                {
                    var file = await container.Root.CreateFileAsync("streamed.txt");
                    using (var writeStream = await file.OpenWriteAsync())
                    {
                        var bytes = Encoding.UTF8.GetBytes("written via a stream");
                        writeStream.Write(bytes, 0, bytes.Length);
                    }

                    Assert.Equal("written via a stream", await file.ReadAllTextAsync());
                }
                finally
                {
                    container.Close();
                }
            }
        }

        [Theory]
        [MemberData(nameof(WritableFixtures))]
        public async Task WriteThenClose_ThenReopenReadOnly_ChangesArePersisted(TestContainers.ContainerFixture fixture)
        {
            // The important end-to-end test: proves a write actually made it to disk through
            // DiscUtils' own Dispose()/flush, not just visible within the same open session's
            // in-memory state. Opens a *fresh* VeraCryptContainer against the same file after fully
            // closing the one that wrote to it.
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);

            var writable = await VeraCryptContainer.OpenAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType,
                accessMode: ContainerAccessMode.ReadWrite);
            writable.IsWritable = true;
            await writable.Root.CreateFileAsync("persisted.txt", new MemoryStream(Encoding.UTF8.GetBytes("still here")));
            writable.Close();

            var reopened = await VeraCryptContainer.OpenAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType);
            try
            {
                var file = await reopened.Root.GetFileAsync("persisted.txt");
                Assert.Equal("still here", await file.ReadAllTextAsync());

                // And the pre-existing fixture content is still intact alongside the new file.
                var original = await reopened.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await original.ReadAllTextAsync());
            }
            finally
            {
                reopened.Close();
            }
        }
    }
}
