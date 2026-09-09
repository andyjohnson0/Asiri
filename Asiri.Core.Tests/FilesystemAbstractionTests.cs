using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for the filesystem abstraction enhancements added by issue #2: Path, Parent, attributes,
    /// timestamps, EnumerateFilesAsync/EnumerateDirectoriesAsync, and IFile.OpenReadAsync. Path/Parent
    /// and OpenReadAsync are tested generically across every fixture in TestContainers.All(), since
    /// all three filesystem backends implement them identically and every fixture already has the
    /// standard test.txt/data/{subtest.txt,image.png} layout. The attribute/timestamp/enumeration
    /// tests need real varied attributes and a directory with more than one file extension, so they
    /// run only against the dedicated AesAttrsExFat fixture - see TestContainers.AesAttrsExFat and
    /// AGENT.md for its structure.
    /// </summary>
    public class FilesystemAbstractionTests
    {
        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Path_MatchesExpectedRootedFormat(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                Assert.Equal("\\", container.Root.Path);

                var data = await container.Root.GetDirectoryAsync("data");
                Assert.Equal("\\data", data.Path);

                var subtest = await data.GetFileAsync("subtest.txt");
                Assert.Equal("\\data\\subtest.txt", subtest.Path);
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Parent_NavigatesBackUpTheTree(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                Assert.Null(container.Root.Parent);

                var data = await container.Root.GetDirectoryAsync("data");
                Assert.Equal("\\", data.Parent.Path);

                var testTxt = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("\\", testTxt.Parent.Path);

                var subtest = await data.GetFileAsync("subtest.txt");
                Assert.Equal(data.Path, subtest.Parent.Path);
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task OpenReadAsync_ReturnsSameContentAsReadAllBytesAsync(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                var data = await container.Root.GetDirectoryAsync("data");
                var image = await data.GetFileAsync("image.png");
                var expected = await image.ReadAllBytesAsync();

                using var stream = await image.OpenReadAsync();
                using var buffer = new MemoryStream();
                await stream.CopyToAsync(buffer);

                Assert.Equal(expected, buffer.ToArray());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task OpenReadAsync_SupportsPartialReads()
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var testTxt = await container.Root.GetFileAsync("test.txt");

                using var stream = await testTxt.OpenReadAsync();
                var buffer = new byte[5];
                var totalRead = 0;
                while (totalRead < buffer.Length)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead));
                    Assert.True(read > 0);
                    totalRead += read;
                }

                Assert.Equal("Hello", System.Text.Encoding.UTF8.GetString(buffer));
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [InlineData("test.txt", FileAttributes.Archive)]
        [InlineData("readonly.txt", FileAttributes.ReadOnly | FileAttributes.Archive)]
        [InlineData("hidden.txt", FileAttributes.Hidden | FileAttributes.Archive)]
        [InlineData("system.txt", FileAttributes.System | FileAttributes.Archive)]
        public async Task GetAttributesAsync_ReturnsExpectedAttributes(string fileName, FileAttributes expected)
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var file = await container.Root.GetFileAsync(fileName);
                var attrs = await file.GetAttributesAsync();

                Assert.Equal(expected, attrs);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task GetAttributesAsync_Directory_HasDirectoryFlag()
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var data = await container.Root.GetDirectoryAsync("data");
                var attrs = await data.GetAttributesAsync();

                Assert.Equal(FileAttributes.Directory, attrs);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task HiddenFile_IsNotFilteredOutOfGetEntriesAsync()
        {
            // Confirms hidden.txt is genuinely readable/discoverable, not silently excluded the way a
            // shell UI might filter it - Asiri exposes everything transparently, same as GetEntriesAsync
            // already does for every other entry.
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var entries = (await container.Root.GetEntriesAsync()).ToList();
                Assert.Contains(entries, e => e.Name == "hidden.txt");
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [InlineData("test.txt")]
        [InlineData("readonly.txt")]
        [InlineData("hidden.txt")]
        [InlineData("system.txt")]
        public async Task GetCreationTimeUtcAsync_AndLastWriteTimeUtcAsync_ArePlausible(string fileName)
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var file = await container.Root.GetFileAsync(fileName);
                var created = await file.GetCreationTimeUtcAsync();
                var written = await file.GetLastWriteTimeUtcAsync();

                AssertPlausibleTimestamp(created);
                AssertPlausibleTimestamp(written);
            }
            finally
            {
                container.Close();
            }
        }

        private static void AssertPlausibleTimestamp(DateTime timestamp)
        {
            // Exact values aren't a practical known-answer here (exFAT's timestamp resolution is
            // coarse, and the value depends on exactly when the fixture was built), so this checks
            // plausibility instead: not the zero/unset value, not absurdly old, not in the future
            // (allowing a little slack for clock skew between machines).
            Assert.True(timestamp > new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc), $"Timestamp implausibly old: {timestamp:O}");
            Assert.True(timestamp < DateTime.UtcNow.AddDays(1), $"Timestamp in the future: {timestamp:O}");
        }

        [Fact]
        public async Task EnumerateFilesAsync_DefaultPattern_ReturnsAllFilesNotDirectories()
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var files = (await container.Root.EnumerateFilesAsync()).ToList();
                var names = files.Select(f => f.Name).ToList();

                Assert.Contains("test.txt", names);
                Assert.Contains("readonly.txt", names);
                Assert.Contains("hidden.txt", names);
                Assert.Contains("system.txt", names);
                Assert.DoesNotContain("data", names);
                Assert.DoesNotContain("other", names);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task EnumerateFilesAsync_SearchPattern_FiltersByExtension()
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var data = await container.Root.GetDirectoryAsync("data");

                var txtFiles = (await data.EnumerateFilesAsync("*.txt")).ToList();

                var onlyFile = Assert.Single(txtFiles);
                Assert.Equal("subtest.txt", onlyFile.Name);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task EnumerateFilesAsync_ReturnsAllFilesInDirectoryWithMultipleFiles()
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var other = await container.Root.GetDirectoryAsync("other");

                var files = (await other.EnumerateFilesAsync()).ToList();
                var names = files.Select(f => f.Name).OrderBy(n => n).ToList();

                Assert.Equal(new[] { "file 1.txt", "file 2.txt", "file 3.txt", "file 4.txt", "file 5.txt" }, names);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task EnumerateFilesAsync_NullSearchPattern_ThrowsArgumentNullException()
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                await Assert.ThrowsAsync<ArgumentNullException>(() => container.Root.EnumerateFilesAsync(null!));
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task EnumerateDirectoriesAsync_DefaultPattern_ContainsExpectedSubdirectories()
        {
            // Uses Contains rather than an exact set: the container also has "System Volume
            // Information" and "$RECYCLE.BIN", both created automatically by Windows when the
            // container was mounted - genuine, if incidental, extra directories.
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var dirs = (await container.Root.EnumerateDirectoriesAsync()).ToList();
                var names = dirs.Select(d => d.Name).ToList();

                Assert.Contains("data", names);
                Assert.Contains("other", names);
                Assert.DoesNotContain("test.txt", names);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task EnumerateDirectoriesAsync_SearchPattern_FiltersByName()
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                var dirs = (await container.Root.EnumerateDirectoriesAsync("d*")).ToList();

                var onlyDir = Assert.Single(dirs);
                Assert.Equal("data", onlyDir.Name);
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task EnumerateDirectoriesAsync_NullSearchPattern_ThrowsArgumentNullException()
        {
            var container = await TestContainers.AesAttrsExFat.OpenAsync();
            try
            {
                await Assert.ThrowsAsync<ArgumentNullException>(() => container.Root.EnumerateDirectoriesAsync(null!));
            }
            finally
            {
                container.Close();
            }
        }
    }
}
