using System.IO;
using System.Threading.Tasks;
using DiscUtils.ExFat;
using uk.andyjohnson.Asiri.Core;
using uk.andyjohnson.Asiri.Core.Tests;

namespace uk.andyjohnson.Asiri.Core.Tests.Filesystem.ExFat
{
    /// <summary>
    /// Tests that <see cref="DecryptedBlockDeviceStream"/> can actually be consumed by a real
    /// filesystem library, using DiscUtils.ExFat directly - exactly the role the stream is meant to
    /// serve. This is test code exercising DiscUtils' own public API against the stream; it does not
    /// implement any filesystem abstraction of Asiri.Core's own (no IDirectory/IFile). It is isolated
    /// under Filesystem/ExFat, mirroring Asiri.Core's own namespace split, since it references
    /// DiscUtils.ExFat directly and must stay independent of the NTFS and FAT equivalents.
    ///
    /// Unlike DiscUtils.Fat, DiscUtils.ExFat.ExFatFileSystem preserves exact case in its directory
    /// enumeration, matching NTFS's behaviour rather than FAT's uppercase 8.3-style names. It also
    /// differs from both NTFS and FAT in the path format GetFileSystemEntries returns: entries have
    /// no leading "\" (e.g. "test.txt" for the root, "data\subtest.txt" for a subdirectory), rather
    /// than the fully-rooted "\test.txt" / "\data\subtest.txt" NTFS and FAT return. Confirmed
    /// empirically before writing these assertions.
    /// </summary>
    public class DecryptedBlockDeviceStreamExFatIntegrationTests
    {
        private static readonly char[] PathSeparators = { '\\' };

        private static async Task<(ExFatFileSystem exFat, DecryptedBlockDeviceStream stream)> CreateExFatFileSystemAsync()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesExFat.ContainerFile, TestContainers.AesExFat.Password, TestContainers.AesExFat.Algorithm, TestContainers.AesExFat.HashAlgorithm);
            var decryptor = await SectorDecryptor.CreateAsync(TestContainers.AesExFat.ContainerFile, header);
            var stream = new DecryptedBlockDeviceStream(decryptor);
            return (new ExFatFileSystem(stream, PathSeparators), stream);
        }

        private static byte[] ReadFile(ExFatFileSystem exFat, string path)
        {
            using var fileStream = exFat.OpenFile(path, FileMode.Open, FileAccess.Read);
            using var memoryStream = new MemoryStream();
            fileStream.CopyTo(memoryStream);
            return memoryStream.ToArray();
        }

        [Fact]
        public async Task ExFatFileSystem_CanBeConstructedDirectlyFromStream()
        {
            var (exFat, stream) = await CreateExFatFileSystemAsync();
            using (exFat)
            using (stream)
            {
                Assert.True(exFat.DirectoryExists(@"\") || exFat.Exists(@"\"));
            }
        }

        [Fact]
        public async Task RootDirectory_CanBeEnumerated()
        {
            var (exFat, stream) = await CreateExFatFileSystemAsync();
            using (exFat)
            using (stream)
            {
                var entries = exFat.GetFileSystemEntries(@"\");

                Assert.Contains("test.txt", entries);
                Assert.Contains("data", entries);
            }
        }

        [Fact]
        public async Task DataSubdirectory_CanBeEnumerated()
        {
            var (exFat, stream) = await CreateExFatFileSystemAsync();
            using (exFat)
            using (stream)
            {
                var entries = exFat.GetFileSystemEntries(@"\data");

                Assert.Contains(@"data\subtest.txt", entries);
                Assert.Contains(@"data\image.png", entries);
            }
        }

        [Fact]
        public async Task TestTxt_HasExpectedContentsAndSize()
        {
            var (exFat, stream) = await CreateExFatFileSystemAsync();
            using (exFat)
            using (stream)
            {
                var bytes = ReadFile(exFat, @"\test.txt");

                Assert.Equal("Hello, world!", System.Text.Encoding.UTF8.GetString(bytes));
                Assert.Equal(bytes.Length, (int)exFat.GetFileLength(@"\test.txt"));
            }
        }

        [Fact]
        public async Task DataSubtestTxt_HasExpectedContentsAndSize()
        {
            var (exFat, stream) = await CreateExFatFileSystemAsync();
            using (exFat)
            using (stream)
            {
                var bytes = ReadFile(exFat, @"\data\subtest.txt");

                Assert.Equal("This is a test.", System.Text.Encoding.UTF8.GetString(bytes));
                Assert.Equal(bytes.Length, (int)exFat.GetFileLength(@"\data\subtest.txt"));
            }
        }

        [Fact]
        public async Task DataImagePng_IsByteForByteIdenticalToProvidedImage()
        {
            var (exFat, stream) = await CreateExFatFileSystemAsync();
            using (exFat)
            using (stream)
            {
                var fromVolume = ReadFile(exFat, @"\data\image.png");
                var expectedPath = Path.Combine(TestContainers.AesExFat.ContainerFile.DirectoryName!, "image.png");
                var expected = File.ReadAllBytes(expectedPath);

                Assert.Equal(expected, fromVolume);
            }
        }
    }
}
