using System;
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
        // Resolved once, relative to this source file's own location (Asiri.Core.Tests, a sibling
        // of "Test Data"), so it is correct regardless of how deeply nested the test file that
        // references a fixture happens to be. Declared first: static field initializers run in
        // declaration order, and the fixtures below - via KeyFile() - depend on this being ready.
        private static readonly string TestDataDirectory = GetTestDataDirectory();

        private static string GetTestDataDirectory([CallerFilePath] string sourceFilePath = "")
        {
            return Path.Combine(Path.GetDirectoryName(sourceFilePath)!, "Test Data");
        }

        /// <summary>A keyfile under "Test Data", for use as a ContainerFixture's KeyFiles.</summary>
        private static FileInfo KeyFile(string fileName)
        {
            return new FileInfo(Path.Combine(TestDataDirectory, fileName));
        }

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

        /// <summary>AES-Twofish / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture AesTwofishExFat = new ContainerFixture(
            "AES-TWOFISH_SHA-512_EXFAT.hc",
            "ExcLtHMJlW)8fb?VD?$L",
            CryptoAlgorithm.AesTwofish,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>AES-Twofish-Serpent / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture AesTwofishSerpentExFat = new ContainerFixture(
            "AES-TWOFISH-SERPENT_SHA-512_EXFAT.hc",
            "EWLe<8ZKGbpiV%Y56C6Z",
            CryptoAlgorithm.AesTwofishSerpent,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>Serpent-AES / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture SerpentAesExFat = new ContainerFixture(
            "SERPENT-AES_SHA-512_EXFAT.hc",
            "H(g0d9$mM4V=al9N1QSM",
            CryptoAlgorithm.SerpentAes,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>Serpent-Twofish-AES / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture SerpentTwofishAesExFat = new ContainerFixture(
            "SERPENT-TWOFISH-AES_SHA-512_EXFAT.hc",
            "PT~gXCJW9jRZraD#Ja5e",
            CryptoAlgorithm.SerpentTwofishAes,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>Twofish-Serpent / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture TwofishSerpentExFat = new ContainerFixture(
            "TWOFISH-SERPENT_SHA-512_EXFAT.hc",
            "BacR-?#R7^2QlAYCOV6y",
            CryptoAlgorithm.TwofishSerpent,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>Camellia-Serpent / SHA-512 / exFAT.</summary>
        public static readonly ContainerFixture CamelliaSerpentExFat = new ContainerFixture(
            "CAMELLIA-SERPENT_SHA-512_EXFAT.hc",
            "AP9AF%XT~LRIKLPC$m=(",
            CryptoAlgorithm.CamelliaSerpent,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat);

        /// <summary>
        /// AES / SHA-512 / exFAT, created with a non-default PIM. Deliberately a small PIM (5, giving
        /// 20,000 PBKDF2 iterations - see HeaderParser.GetPbkdf2IterationCount) rather than a
        /// VeraCrypt-realistic one, so this fixture is actually cheaper to open than the 500,000-
        /// iteration default fixtures, not more expensive.
        /// </summary>
        public static readonly ContainerFixture AesPim5ExFat = new ContainerFixture(
            "AES_SHA-512_EXFAT_PIM5.hc",
            "(a~ojGZpRQSSlTSzfjPU",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat,
            pim: 5);

        /// <summary>
        /// AES / Whirlpool / exFAT, created with a non-default PIM (20, giving 35,000 iterations) - a
        /// different PIM value and a different hash from <see cref="AesPim5ExFat"/>, as an independent
        /// real-world check of the PIM formula rather than relying on one data point.
        /// </summary>
        public static readonly ContainerFixture AesPim20ExFat = new ContainerFixture(
            "AES_WHIRLPOOL_EXFAT_PIM20.hc",
            "bZ0VulQNxLOW^CK3k(lr",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Whirlpool,
            FileSystemType.ExFat,
            pim: 20);

        /// <summary>AES / SHA-512 / exFAT, secured by password + one keyfile.</summary>
        public static readonly ContainerFixture AesKf1ExFat = new ContainerFixture(
            "AES_SHA-512_EXFAT_KF1.hc",
            "wVMm#SsQRh5XdxPAr^mC",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat,
            keyFiles: new[] { KeyFile("Keyfile1.bin") });

        /// <summary>AES / SHA-512 / exFAT, secured by one keyfile only - an empty password.</summary>
        public static readonly ContainerFixture AesKf1EmptyPasswordExFat = new ContainerFixture(
            "AES_SHA-512_EXFAT_KF1_EMPTYPW.hc",
            "",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat,
            keyFiles: new[] { KeyFile("Keyfile1.bin") });

        /// <summary>AES / SHA-512 / exFAT, secured by password + two keyfiles together.</summary>
        public static readonly ContainerFixture AesKf1Kf2ExFat = new ContainerFixture(
            "AES_SHA-512_EXFAT_KF1_KF2.hc",
            "eCn8nAr-eK0tLhj)ceFP",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat,
            keyFiles: new[] { KeyFile("Keyfile1.bin"), KeyFile("Keyfile2.bin") });

        /// <summary>
        /// AES / SHA-512 / exFAT, secured by a keyfile and a password longer than 64 bytes - the
        /// threshold (see KeyfileMixer) above which VeraCrypt uses a 128-byte mixing pool instead of
        /// the 64-byte one every other fixture's shorter password selects.
        /// </summary>
        public static readonly ContainerFixture AesKf1LongPasswordExFat = new ContainerFixture(
            "AES_SHA-512_EXFAT_KF1_LONGPW.hc",
            "~wacqaRl)mfCtNY>IGT%nhL~SLzHWW%9iPnHgPQt6Wj8s1F9(w=Jc<4<1pSaUkd%UTD4)-1h~KJAmhTq",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
            FileSystemType.ExFat,
            keyFiles: new[] { KeyFile("Keyfile1.bin") });

        /// <summary>
        /// AES / SHA-512 / exFAT, built specifically for filesystem-abstraction tests (Path, Parent,
        /// attributes, timestamps, EnumerateFilesAsync/EnumerateDirectoriesAsync search patterns).
        /// Root also contains "System Volume Information" and "$RECYCLE.BIN", both Hidden+System
        /// directories created automatically by Windows when the container was mounted - real,
        /// unplanned extra data, left in deliberately rather than cleaned up, since it's a genuine
        /// (if incidental) example of hidden/system entries no test asked for. See
        /// AGENT.md for the full structure.
        /// </summary>
        public static readonly ContainerFixture AesAttrsExFat = new ContainerFixture(
            "AES_SHA-512_EXFAT_ATTRS.hc",
            "ZlWjwD>EW)RP76IiMKfz",
            CryptoAlgorithm.Aes,
            HashAlgorithm.Sha512,
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
            yield return new object[] { AesTwofishExFat };
            yield return new object[] { AesTwofishSerpentExFat };
            yield return new object[] { SerpentAesExFat };
            yield return new object[] { SerpentTwofishAesExFat };
            yield return new object[] { TwofishSerpentExFat };
            yield return new object[] { CamelliaSerpentExFat };
            yield return new object[] { AesPim5ExFat };
            yield return new object[] { AesPim20ExFat };
            yield return new object[] { AesKf1ExFat };
            yield return new object[] { AesKf1EmptyPasswordExFat };
            yield return new object[] { AesKf1Kf2ExFat };
            yield return new object[] { AesKf1LongPasswordExFat };
            yield return new object[] { AesAttrsExFat };
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

            /// <summary>The PIM this container was created with, or 0 if it uses the default.</summary>
            public int Pim { get; }

            /// <summary>The keyfiles this container was created with, or empty if none.</summary>
            public IReadOnlyList<FileInfo> KeyFiles { get; }

            public ContainerFixture(string fileName, string password, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, FileSystemType filesystemType, int pim = 0, IReadOnlyList<FileInfo>? keyFiles = null)
            {
                ContainerFile = new FileInfo(Path.Combine(TestDataDirectory, fileName));
                Password = password;
                Algorithm = algorithm;
                HashAlgorithm = hashAlgorithm;
                FilesystemType = filesystemType;
                Pim = pim;
                KeyFiles = keyFiles ?? Array.Empty<FileInfo>();
            }

            /// <summary>Opens this container via the full public VeraCryptContainer.OpenAsync API.</summary>
            public Task<VeraCryptContainer> OpenAsync()
            {
                return VeraCryptContainer.OpenAsync(ContainerFile, Password, Algorithm, HashAlgorithm, FilesystemType, Pim, KeyFiles);
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
