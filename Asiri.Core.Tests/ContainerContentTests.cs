using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests that VeraCryptContainer's IDirectory/IFile abstraction layer returns correct content
    /// for every registered test container (see <see cref="TestContainers"/>), regardless of the
    /// underlying filesystem backend. Every container in the test matrix shares the same
    /// file/directory layout by design (test.txt, data/subtest.txt, data/image.png), so these
    /// assertions are written once and run against each container via [Theory]/[MemberData] rather
    /// than duplicated per filesystem type.
    ///
    /// Name comparisons here are case-insensitive: unlike NTFS, which preserves case,
    /// DiscUtils.Fat's directory enumeration returns short, uppercase 8.3-style names (e.g.
    /// "TEST.TXT") regardless of the case a file was created with, so FatDirectory/FatFile's Name
    /// faithfully reflects that. Confirmed empirically before adjusting these assertions - see
    /// Filesystem/Fat/DecryptedBlockDeviceStreamFatIntegrationTests.cs for the equivalent
    /// observation against DiscUtils.Fat directly. Path *lookups* (GetFile/GetDirectory) are
    /// unaffected either way, since DiscUtils.Fat resolves them case-insensitively regardless of
    /// what case is passed in.
    ///
    /// Tests that genuinely need a concrete DiscUtils type - e.g. proving DiscUtils.Ntfs or
    /// DiscUtils.Fat can consume the Stage 3 stream directly, bypassing IDirectory/IFile entirely -
    /// are filesystem-specific by nature and live under Filesystem/Ntfs and Filesystem/Fat instead.
    /// </summary>
    public class ContainerContentTests
    {
        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Root_Name_IsEmptyString(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                Assert.Equal(string.Empty, container.Root.Name);
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Root_GetEntriesAsync_ContainsExpectedNamesAndTypes(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                var entries = (await container.Root.GetEntriesAsync()).ToList();

                var testTxt = Assert.Single(entries, e => string.Equals(e.Name, "test.txt", StringComparison.OrdinalIgnoreCase));
                Assert.IsAssignableFrom<IFile>(testTxt);

                var data = Assert.Single(entries, e => string.Equals(e.Name, "data", StringComparison.OrdinalIgnoreCase));
                Assert.IsAssignableFrom<IDirectory>(data);
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Root_GetFileAsync_TestTxt_ReturnsExpectedContentsAndSize(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                var file = await container.Root.GetFileAsync("test.txt");

                Assert.Equal("Hello, world!", await file.ReadAllTextAsync());
                Assert.Equal(Encoding.UTF8.GetByteCount("Hello, world!"), await file.GetLengthAsync());
                Assert.Equal(await file.GetLengthAsync(), (await file.ReadAllBytesAsync()).Length);
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task Root_GetDirectoryAsync_Data_HasExpectedNameAndEntries(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                var data = await container.Root.GetDirectoryAsync("data");

                Assert.Equal("data", data.Name, StringComparer.OrdinalIgnoreCase);
                var names = (await data.GetEntriesAsync()).Select(e => e.Name).ToList();
                Assert.Contains("subtest.txt", names, StringComparer.OrdinalIgnoreCase);
                Assert.Contains("image.png", names, StringComparer.OrdinalIgnoreCase);
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task DataDirectory_GetFileAsync_SubtestTxt_ReturnsExpectedContentsAndSize(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                var dataDir = await container.Root.GetDirectoryAsync("data");
                var file = await dataDir.GetFileAsync("subtest.txt");

                Assert.Equal("This is a test.", await file.ReadAllTextAsync());
                Assert.Equal(Encoding.UTF8.GetByteCount("This is a test."), await file.GetLengthAsync());
                Assert.Equal(await file.GetLengthAsync(), (await file.ReadAllBytesAsync()).Length);
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task DataDirectory_GetFileAsync_ImagePng_IsByteForByteIdenticalToProvidedImage(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                var dataDir = await container.Root.GetDirectoryAsync("data");
                var file = await dataDir.GetFileAsync("image.png");
                var expectedPath = Path.Combine(fixture.ContainerFile.DirectoryName!, "image.png");
                var expected = File.ReadAllBytes(expectedPath);

                Assert.Equal(expected, await file.ReadAllBytesAsync());
                Assert.Equal(expected.Length, await file.GetLengthAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(TestContainers.All), MemberType = typeof(TestContainers))]
        public async Task FileObtainedViaGetEntriesAsync_ReturnsSameContentAsFileObtainedViaGetFileAsync(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                var entries = await container.Root.GetEntriesAsync();
                var viaEntries = (IFile)entries.Single(e => string.Equals(e.Name, "test.txt", StringComparison.OrdinalIgnoreCase));
                var viaGetFile = await container.Root.GetFileAsync("test.txt");

                Assert.Equal(await viaGetFile.ReadAllBytesAsync(), await viaEntries.ReadAllBytesAsync());
            }
            finally
            {
                container.Close();
            }
        }
    }
}
