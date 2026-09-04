using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using DiscUtils.Ntfs;
using uk.andyjohnson.Asiri.Core;
using uk.andyjohnson.Asiri.Core.Tests;

namespace uk.andyjohnson.Asiri.Core.Tests.Filesystem.Ntfs
{
    /// <summary>
    /// Tests that <see cref="DecryptedBlockDeviceStream"/> can actually be consumed by a real
    /// filesystem library, using DiscUtils.Ntfs directly - exactly the role the stream is meant to
    /// serve, and the strongest possible proof of correctness for Stages 1-3 combined. This is test
    /// code exercising DiscUtils' own public API against the stream; it does not implement any
    /// filesystem abstraction of Asiri.Core's own (no IDirectory/IFile). It is isolated under
    /// Filesystem/Ntfs, mirroring Asiri.Core's own namespace split, since a future filesystem type
    /// would need its own parallel proof rather than a change here.
    /// </summary>
    public class DecryptedBlockDeviceStreamNtfsIntegrationTests
    {
        private static async Task<(NtfsFileSystem ntfs, DecryptedBlockDeviceStream stream)> CreateNtfsFileSystemAsync()
        {
            var header = await HeaderParser.ParseAsync(TestContainers.AesNtfs.ContainerFile, TestContainers.AesNtfs.Password, TestContainers.AesNtfs.Algorithm, TestContainers.AesNtfs.HashAlgorithm);
            var decryptor = await SectorDecryptor.CreateAsync(TestContainers.AesNtfs.ContainerFile, header);
            var stream = new DecryptedBlockDeviceStream(decryptor);
            return (new NtfsFileSystem(stream), stream);
        }

        private static byte[] ReadFile(NtfsFileSystem ntfs, string path)
        {
            using var fileStream = ntfs.OpenFile(path, FileMode.Open, FileAccess.Read);
            using var memoryStream = new MemoryStream();
            fileStream.CopyTo(memoryStream);
            return memoryStream.ToArray();
        }

        [Fact]
        public async Task NtfsFileSystem_CanBeConstructedDirectlyFromStream()
        {
            var (ntfs, stream) = await CreateNtfsFileSystemAsync();
            using (ntfs)
            using (stream)
            {
                Assert.True(ntfs.Exists(@"\"));
            }
        }

        [Fact]
        public async Task RootDirectory_CanBeEnumerated()
        {
            var (ntfs, stream) = await CreateNtfsFileSystemAsync();
            using (ntfs)
            using (stream)
            {
                var entries = ntfs.GetFileSystemEntries(@"\");

                Assert.Contains(@"\test.txt", entries);
                Assert.Contains(@"\data", entries);
            }
        }

        [Fact]
        public async Task DataSubdirectory_CanBeEnumerated()
        {
            var (ntfs, stream) = await CreateNtfsFileSystemAsync();
            using (ntfs)
            using (stream)
            {
                var entries = ntfs.GetFileSystemEntries(@"\data");

                Assert.Contains(@"\data\subtest.txt", entries);
                Assert.Contains(@"\data\image.png", entries);
            }
        }

        [Fact]
        public async Task TestTxt_HasExpectedContentsAndSize()
        {
            var (ntfs, stream) = await CreateNtfsFileSystemAsync();
            using (ntfs)
            using (stream)
            {
                var bytes = ReadFile(ntfs, @"\test.txt");

                Assert.Equal("Hello, world!", System.Text.Encoding.UTF8.GetString(bytes));
                Assert.Equal(bytes.Length, (int)ntfs.GetFileLength(@"\test.txt"));
            }
        }

        [Fact]
        public async Task DataSubtestTxt_HasExpectedContentsAndSize()
        {
            var (ntfs, stream) = await CreateNtfsFileSystemAsync();
            using (ntfs)
            using (stream)
            {
                var bytes = ReadFile(ntfs, @"\data\subtest.txt");

                Assert.Equal("This is a test.", System.Text.Encoding.UTF8.GetString(bytes));
                Assert.Equal(bytes.Length, (int)ntfs.GetFileLength(@"\data\subtest.txt"));
            }
        }

        [Fact]
        public async Task DataImagePng_IsByteForByteIdenticalToProvidedImage()
        {
            var (ntfs, stream) = await CreateNtfsFileSystemAsync();
            using (ntfs)
            using (stream)
            {
                var fromVolume = ReadFile(ntfs, @"\data\image.png");
                var expectedPath = Path.Combine(TestContainers.AesNtfs.ContainerFile.DirectoryName!, "image.png");
                var expected = File.ReadAllBytes(expectedPath);

                Assert.Equal(expected, fromVolume);
            }
        }
    }
}
