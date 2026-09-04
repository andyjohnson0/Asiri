using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Central catalog of the VeraCrypt test containers under "Test Data", together with the
    /// password and (algorithm, filesystem) permutation each was created with. Add a new fixture
    /// here - alongside the corresponding file under "Test Data" - for each new permutation
    /// supplied, rather than duplicating a filename/password/path-resolution helper in every test
    /// file that needs a container. Each container has its own, independent password, by design,
    /// so that no test can accidentally succeed against the wrong container.
    /// </summary>
    public static class TestContainers
    {
        /// <summary>AES / SHA-512 / NTFS.</summary>
        public static readonly ContainerFixture AesNtfs = new ContainerFixture(
            "AES_SHA-512_NTFS.hc",
            "A67m4$2c+V57#2AWq8d3",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
            FileSystemType.Ntfs);

        /// <summary>AES / SHA-512 / FAT16.</summary>
        public static readonly ContainerFixture AesFat16 = new ContainerFixture(
            "AES_SHA-512_FAT16.hc",
            "85dRp6-OL72^L892WcqH",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
            FileSystemType.Fat);

        /// <summary>AES / SHA-512 / FAT32.</summary>
        public static readonly ContainerFixture AesFat32 = new ContainerFixture(
            "AES_SHA-512_FAT32.hc",
            "Uhf59~tTr30fH?52SD15",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
            FileSystemType.Fat);

        /// <summary>AES / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture AesExFat = new ContainerFixture(
            "AES_SHA-512_EXFAT.hc",
            "kr2Y8+7vfENl08dR1cFn",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>Serpent / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture SerpentExFat = new ContainerFixture(
            "SERPENT_SHA-512_EXFAT.hc",
            "3f8L+2v9#1qW$5dR7gH0",
            CryptoAlgorithm.Serpent,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>Twofish / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture TwofishExFat = new ContainerFixture(
            "TWOFISH_SHA-512_EXFAT.hc",
            "hR6ndf0-R9N7$qA4+=5B",
            CryptoAlgorithm.Twofish,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>Camellia / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture CamelliaExFat = new ContainerFixture(
            "CAMELLIA_SHA-512_EXFAT.hc",
            "6N7$K(r56Cf~Plhdr48D",
            CryptoAlgorithm.Camellia,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>AES / SHA-256 / exFAT.</summary>
        public static readonly ContainerFixture AesSha256ExFat = new ContainerFixture(
            "AES_SHA-256_EXFAT.hc",
            "N^6reU50+3%FGc43>P8s",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha256,
            FileSystemType.ExFat);

        /// <summary>AES / Whirlpool / exFAT.</summary>
        public static readonly ContainerFixture AesWhirlpoolExFat = new ContainerFixture(
            "AES_WHIRLPOOL_EXFAT.hc",
            "FR7cg0-5%9SnmK02zRT2",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Whirlpool,
            FileSystemType.ExFat);

        /// <summary>AES / BLAKE2s-256 / exFAT.</summary>
        public static readonly ContainerFixture AesBlake2s256ExFat = new ContainerFixture(
            "AES_BLAKE2s-256_EXFAT.hc",
            "9Q8$P(m45Rf~Olnh79E6",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Blake2s256,
            FileSystemType.ExFat);

        // Add further fixtures here as new (algorithm, filesystem) permutations are supplied, and
        // include them in All() below so shared, filesystem-agnostic tests pick them up
        // automatically.

        /// <summary>
        /// Every registered container, as an xUnit [MemberData] source, for tests that should run
        /// identically against each one (content correctness through IDirectory/IFile, and the
        /// filesystem-agnostic Open/Close contract).
        /// </summary>
        public static IEnumerable<object[]> All()
        {
            yield return new object[] { AesNtfs };
            yield return new object[] { AesFat16 };
            yield return new object[] { AesFat32 };
            yield return new object[] { AesExFat };
            yield return new object[] { SerpentExFat };
            yield return new object[] { TwofishExFat };
            yield return new object[] { CamelliaExFat };
            yield return new object[] { AesSha256ExFat };
            yield return new object[] { AesWhirlpoolExFat };
            yield return new object[] { AesBlake2s256ExFat };
        }

        /// <summary>
        /// A single VeraCrypt test container: its file, password, and the (algorithm, hash,
        /// filesystem) permutation it was created with.
        /// </summary>
        public sealed class ContainerFixture
        {
            private static readonly string TestDataDirectory = GetTestDataDirectory();

            public FileInfo ContainerFile { get; }
            public string Password { get; }
            public CryptoAlgorithm Algorithm { get; }
            public HashAlgorithm HashAlgorithm { get; }
            public FileSystemType FilesystemType { get; }

            public ContainerFixture(string fileName, string password, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, FileSystemType filesystemType)
            {
                ContainerFile = new FileInfo(Path.Combine(TestDataDirectory, fileName));
                Password = password;
                Algorithm = algorithm;
                HashAlgorithm = hashAlgorithm;
                FilesystemType = filesystemType;
            }

            /// <summary>Opens this container via the full public VeraCryptContainer.OpenAsync API.</summary>
            public Task<VeraCryptContainer> OpenAsync()
            {
                return VeraCryptContainer.OpenAsync(ContainerFile, Password, Algorithm, HashAlgorithm, FilesystemType);
            }

            // Used by the xUnit test runner to label [Theory] cases in output; without this, every
            // row would display as the unhelpful "TestContainers+ContainerFixture".
            public override string ToString()
            {
                return ContainerFile.Name;
            }

            // Resolved once, relative to this source file's own location (Asiri.Core.Tests, a sibling
            // of "Test Data"), so it is correct regardless of how deeply nested the test file that
            // references a fixture happens to be.
            private static string GetTestDataDirectory([CallerFilePath] string sourceFilePath = "")
            {
                return Path.Combine(Path.GetDirectoryName(sourceFilePath)!, "Test Data");
            }
        }
    }
}
