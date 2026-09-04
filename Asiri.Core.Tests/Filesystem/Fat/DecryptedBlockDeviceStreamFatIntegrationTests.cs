using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using DiscUtils.Fat;
using uk.andyjohnson.Asiri.Core;
using uk.andyjohnson.Asiri.Core.Tests;

namespace uk.andyjohnson.Asiri.Core.Tests.Filesystem.Fat
{
    /// <summary>
    /// Tests that <see cref="DecryptedBlockDeviceStream"/> can actually be consumed by a real
    /// filesystem library, using DiscUtils.Fat directly - exactly the role the stream is meant to
    /// serve. This is test code exercising DiscUtils' own public API against the stream; it does not
    /// implement any filesystem abstraction of Asiri.Core's own (no IDirectory/IFile). It is isolated
    /// under Filesystem/Fat, mirroring Asiri.Core's own namespace split, since it references
    /// DiscUtils.Fat directly and must stay independent of the NTFS equivalent.
    ///
    /// Runs against both the FAT16 and FAT32 test containers via [Theory]/[MemberData], since
    /// DiscUtils.Fat.FatFileSystem exposes an identical API for both variants - there is nothing
    /// variant-specific to test differently between them here.
    ///
    /// FAT's raw directory enumeration returns short, uppercase 8.3-style names (e.g. "\TEST.TXT")
    /// regardless of the case files were created with, unlike NTFS's case-preserving enumeration;
    /// path lookups (Exists/FileExists/DirectoryExists/OpenFile/GetFileLength) are case-insensitive
    /// regardless. Confirmed empirically against both containers before writing these assertions.
    /// </summary>
    public class DecryptedBlockDeviceStreamFatIntegrationTests
    {
        public static IEnumerable<object[]> FatContainers()
        {
            yield return new object[] { TestContainers.AesFat16 };
            yield return new object[] { TestContainers.AesFat32 };
        }

        private static async Task<(FatFileSystem fat, DecryptedBlockDeviceStream stream)> CreateFatFileSystemAsync(TestContainers.ContainerFixture fixture)
        {
            var header = await HeaderParser.ParseAsync(fixture.ContainerFile, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm);
            var decryptor = await SectorDecryptor.CreateAsync(fixture.ContainerFile, header);
            var stream = new DecryptedBlockDeviceStream(decryptor);
            return (new FatFileSystem(stream), stream);
        }

        private static byte[] ReadFile(FatFileSystem fat, string path)
        {
            using var fileStream = fat.OpenFile(path, FileMode.Open, FileAccess.Read);
            using var memoryStream = new MemoryStream();
            fileStream.CopyTo(memoryStream);
            return memoryStream.ToArray();
        }

        [Theory]
        [MemberData(nameof(FatContainers))]
        public async Task FatFileSystem_CanBeConstructedDirectlyFromStream(TestContainers.ContainerFixture fixture)
        {
            var (fat, stream) = await CreateFatFileSystemAsync(fixture);
            using (fat)
            using (stream)
            {
                // Unlike DiscUtils.Ntfs, DiscUtils.Fat's Exists/DirectoryExists/FileExists all return
                // false for the root path itself (confirmed empirically: FAT's root directory is not
                // represented as a conventional directory entry the way NTFS's is), even though the
                // root is fully valid and enumerable. GetFileSystemEntries is the meaningful "did this
                // actually construct" check here.
                Assert.NotEmpty(fat.GetFileSystemEntries(@"\"));
            }
        }

        [Theory]
        [MemberData(nameof(FatContainers))]
        public async Task RootDirectory_CanBeEnumerated(TestContainers.ContainerFixture fixture)
        {
            var (fat, stream) = await CreateFatFileSystemAsync(fixture);
            using (fat)
            using (stream)
            {
                var entries = fat.GetFileSystemEntries(@"\");

                Assert.Contains(@"\TEST.TXT", entries, StringComparer.OrdinalIgnoreCase);
                Assert.Contains(@"\DATA", entries, StringComparer.OrdinalIgnoreCase);
            }
        }

        [Theory]
        [MemberData(nameof(FatContainers))]
        public async Task DataSubdirectory_CanBeEnumerated(TestContainers.ContainerFixture fixture)
        {
            var (fat, stream) = await CreateFatFileSystemAsync(fixture);
            using (fat)
            using (stream)
            {
                var entries = fat.GetFileSystemEntries(@"\data");

                Assert.Contains(@"\DATA\SUBTEST.TXT", entries, StringComparer.OrdinalIgnoreCase);
                Assert.Contains(@"\DATA\IMAGE.PNG", entries, StringComparer.OrdinalIgnoreCase);
            }
        }

        [Theory]
        [MemberData(nameof(FatContainers))]
        public async Task TestTxt_HasExpectedContentsAndSize(TestContainers.ContainerFixture fixture)
        {
            var (fat, stream) = await CreateFatFileSystemAsync(fixture);
            using (fat)
            using (stream)
            {
                var bytes = ReadFile(fat, @"\test.txt");

                Assert.Equal("Hello, world!", System.Text.Encoding.UTF8.GetString(bytes));
                Assert.Equal(bytes.Length, (int)fat.GetFileLength(@"\test.txt"));
            }
        }

        [Theory]
        [MemberData(nameof(FatContainers))]
        public async Task DataSubtestTxt_HasExpectedContentsAndSize(TestContainers.ContainerFixture fixture)
        {
            var (fat, stream) = await CreateFatFileSystemAsync(fixture);
            using (fat)
            using (stream)
            {
                var bytes = ReadFile(fat, @"\data\subtest.txt");

                Assert.Equal("This is a test.", System.Text.Encoding.UTF8.GetString(bytes));
                Assert.Equal(bytes.Length, (int)fat.GetFileLength(@"\data\subtest.txt"));
            }
        }

        [Theory]
        [MemberData(nameof(FatContainers))]
        public async Task DataImagePng_IsByteForByteIdenticalToProvidedImage(TestContainers.ContainerFixture fixture)
        {
            var (fat, stream) = await CreateFatFileSystemAsync(fixture);
            using (fat)
            using (stream)
            {
                var fromVolume = ReadFile(fat, @"\data\image.png");
                var expectedPath = Path.Combine(fixture.ContainerFile.DirectoryName!, "image.png");
                var expected = File.ReadAllBytes(expectedPath);

                Assert.Equal(expected, fromVolume);
            }
        }

        [Theory]
        [MemberData(nameof(FatContainers))]
        public async Task FatVariant_IsFat16OrFat32(TestContainers.ContainerFixture fixture)
        {
            // Confirms the container's actual on-disk variant is one DiscUtils genuinely recognizes
            // as FAT, not a misdetection of unrelated data (see VeraCryptContainer's OpenFatAsync,
            // which rejects anything other than Fat16/Fat32 for exactly this reason).
            var (fat, stream) = await CreateFatFileSystemAsync(fixture);
            using (fat)
            using (stream)
            {
                Assert.True(fat.FatVariant == FatType.Fat16 || fat.FatVariant == FatType.Fat32,
                    $"Expected Fat16 or Fat32, got {fat.FatVariant}.");
            }
        }
    }
}
