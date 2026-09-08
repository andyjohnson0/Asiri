using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils;
using DiscUtils.ExFat;
using DiscUtils.Fat;
using DiscUtils.Ntfs;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core.Crypto;
using uk.andyjohnson.Asiri.Core.Filesystem.ExFat;
using uk.andyjohnson.Asiri.Core.Filesystem.Fat;
using uk.andyjohnson.Asiri.Core.Filesystem.Ntfs;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// The encryption algorithm used to encrypt a VeraCrypt container: either a single cipher, or
    /// one of VeraCrypt's supported cascades of two or three ciphers applied in sequence. Kuznyechik
    /// and any cascade involving it are out of scope and not represented here.
    /// </summary>
    public enum CryptoAlgorithm
    {
        /// <summary>AES.</summary>
        Aes,

        /// <summary>Serpent.</summary>
        Serpent,

        /// <summary>Twofish.</summary>
        Twofish,

        /// <summary>Camellia.</summary>
        Camellia,

        /// <summary>AES-Twofish cascade.</summary>
        AesTwofish,

        /// <summary>AES-Twofish-Serpent cascade.</summary>
        AesTwofishSerpent,

        /// <summary>Serpent-AES cascade.</summary>
        SerpentAes,

        /// <summary>Serpent-Twofish-AES cascade.</summary>
        SerpentTwofishAes,

        /// <summary>Twofish-Serpent cascade.</summary>
        TwofishSerpent,

        /// <summary>Camellia-Serpent cascade.</summary>
        CamelliaSerpent
    }

    /// <summary>
    /// The hash algorithm used to derive keys from the container password, via PBKDF2. VeraCrypt
    /// allows this to be selected independently of the encryption algorithm.
    /// </summary>
    public enum HashAlgorithm
    {
        /// <summary>SHA-512.</summary>
        Sha512,

        /// <summary>SHA-256.</summary>
        Sha256,

        /// <summary>Whirlpool.</summary>
        Whirlpool,

        /// <summary>BLAKE2s-256.</summary>
        Blake2s256
    }

    /// <summary>
    /// The filesystem type used within a VeraCrypt container. The architecture allows for multiple
    /// filesystem types.
    /// </summary>
    public enum FileSystemType
    {
        /// <summary>NTFS.</summary>
        Ntfs,

        /// <summary>
        /// FAT, in its FAT16 or FAT32 variant. The variant is not a caller choice: it is a
        /// consequence of the volume's size, fixed when the container was created, and is detected
        /// automatically rather than requested.
        /// </summary>
        Fat,

        /// <summary>exFAT.</summary>
        ExFat
    }


    /// <summary>
    /// Provides read-only access to the contents of a VeraCrypt encrypted file container.
    /// </summary>
    public sealed class VeraCryptContainer
    {
        private readonly DecryptedBlockDeviceStream _stream;
        private readonly DiscFileSystem _fileSystem;
        private readonly ContainerLifetime _lifetime;

        private VeraCryptContainer(
            DecryptedBlockDeviceStream stream, DiscFileSystem fileSystem, ContainerLifetime lifetime, IDirectory root,
            CryptoAlgorithm algorithm, FileSystemType fileSystemType)
        {
            _stream = stream;
            _fileSystem = fileSystem;
            _lifetime = lifetime;
            Root = root;
            Algorithm = algorithm;
            FileSystemType = fileSystemType;
        }

        /// <summary>
        /// Opens a VeraCrypt container.
        /// </summary>
        /// <param name="path">Path to the VeraCrypt container file.</param>
        /// <param name="password">The container password.</param>
        /// <param name="algo">The encryption algorithm used by the container.</param>
        /// <param name="hashAlgo">The hash algorithm used to derive keys from the password.</param>
        /// <param name="fsType">The filesystem type used within the container.</param>
        /// <param name="pim">
        /// The container's PIM (Personal Iterations Multiplier), or 0 - the default - if none was
        /// set when the container was created. VeraCrypt does not store the PIM in the header, so it
        /// must be supplied here, the same way the password is.
        /// </param>
        /// <param name="keyFiles">
        /// Keyfiles to mix into the password, in order, or null - the default - for none. VeraCrypt
        /// does not store keyfiles in the header, so, like the password and PIM, they must be
        /// supplied here.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A container whose <see cref="Root"/> exposes the decrypted filesystem.</returns>
        public static async Task<VeraCryptContainer> OpenAsync(
            FileInfo path,
            string password,
            CryptoAlgorithm algo,
            HashAlgorithm hashAlgo,
            FileSystemType fsType,
            int pim = 0,
            IEnumerable<FileInfo> keyFiles = null,
            CancellationToken cancellationToken = default)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            if (!CascadeDefinitions.IsSupported(algo))
            {
                throw new ArgumentException($"Unsupported encryption algorithm: {algo}.", nameof(algo));
            }

            switch (hashAlgo)
            {
                case HashAlgorithm.Sha512:
                case HashAlgorithm.Sha256:
                case HashAlgorithm.Whirlpool:
                case HashAlgorithm.Blake2s256:
                    break;
                default:
                    throw new ArgumentException($"Unsupported hash algorithm: {hashAlgo}.", nameof(hashAlgo));
            }

            switch (fsType)
            {
                case FileSystemType.Ntfs:
                case FileSystemType.Fat:
                case FileSystemType.ExFat:
                    break;
                default:
                    throw new ArgumentException($"Unsupported filesystem type: {fsType}.", nameof(fsType));
            }
            if (pim < 0)
            {
                throw new ArgumentException($"PIM must not be negative: {pim}.", nameof(pim));
            }

            var header = await HeaderParser.ParseAsync(path, password, algo, hashAlgo, pim, keyFiles, cancellationToken).ConfigureAwait(false);
            var decryptor = await SectorDecryptor.CreateAsync(path, header, cancellationToken).ConfigureAwait(false);
            var stream = new DecryptedBlockDeviceStream(decryptor);

            try
            {
                var lifetime = new ContainerLifetime();
                var (fileSystem, root) = await OpenFileSystemAsync(fsType, stream, lifetime, cancellationToken).ConfigureAwait(false);
                return new VeraCryptContainer(stream, fileSystem, lifetime, root, algo, fsType);
            }
            catch
            {
                // Covers both genuine filesystem-open failures and cancellation firing after the
                // stream/decryptor were created but before a filesystem was successfully opened -
                // stream.Dispose() is idempotent (via SectorDecryptor's own disposed-tracking), so
                // this is safe even if the failing step already cleaned up after itself.
                stream.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Opens a VeraCrypt container without knowing its encryption algorithm, hash algorithm, or
        /// filesystem type in advance - only the password is required, matching how VeraCrypt itself
        /// mounts a volume.
        /// </summary>
        /// <remarks>
        /// The (algorithm, hash) combination cannot be known in advance: the only way to tell whether
        /// a combination is correct is to derive keys with it and check whether the header's CRC
        /// validates, so that pairing must genuinely be searched. This searches over
        /// <see cref="HeaderParser.TryDecryptRegionAsync"/> rather than looping
        /// <see cref="HeaderParser.ParseAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, int, IEnumerable{FileInfo}, CancellationToken)"/>
        /// directly, so the header regions are read from disk once and each combination is tried
        /// against the same bytes, rather than re-opening and re-reading the file per attempt.
        ///
        /// The filesystem type, by contrast, is not searched for: once the header decrypts
        /// correctly, the volume's boot sector can be read directly and its OEM ID signature
        /// inspected to determine NTFS, exFAT, or (by elimination) FAT - see
        /// <see cref="DetectFileSystemTypeAsync"/>.
        /// </remarks>
        /// <param name="path">Path to the VeraCrypt container file.</param>
        /// <param name="password">The container password.</param>
        /// <param name="pim">
        /// The container's PIM (Personal Iterations Multiplier), or 0 - the default - if none was
        /// set when the container was created. Unlike the encryption and hash algorithms, this is
        /// never searched for - VeraCrypt does not store the PIM in the header, so, exactly like the
        /// password, it must already be known and supplied by the caller. The same value is used for
        /// every (algorithm, hash) combination the search tries.
        /// </param>
        /// <param name="keyFiles">
        /// Keyfiles to mix into the password, in order, or null - the default - for none. Like PIM,
        /// this is never searched for - the same keyfiles are used for every (algorithm, hash)
        /// combination the search tries.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A container whose <see cref="Root"/> exposes the decrypted filesystem.</returns>
        public static async Task<VeraCryptContainer> OpenAsync(
            FileInfo path,
            string password,
            int pim = 0,
            IEnumerable<FileInfo> keyFiles = null,
            CancellationToken cancellationToken = default)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            if (pim < 0)
            {
                throw new ArgumentException($"PIM must not be negative: {pim}.", nameof(pim));
            }

            var header = await DetectHeaderAsync(path, password, pim, keyFiles, cancellationToken).ConfigureAwait(false);
            if (header == null)
            {
                throw new InvalidOperationException(
                    "Failed to decrypt the VeraCrypt volume header with any supported algorithm. " +
                    "The password may be incorrect, or the container may not be a valid VeraCrypt volume.");
            }

            var decryptor = await SectorDecryptor.CreateAsync(path, header, cancellationToken).ConfigureAwait(false);
            var stream = new DecryptedBlockDeviceStream(decryptor);

            try
            {
                var fsType = await DetectFileSystemTypeAsync(decryptor, cancellationToken).ConfigureAwait(false);
                var lifetime = new ContainerLifetime();
                var (fileSystem, root) = await OpenFileSystemAsync(fsType, stream, lifetime, cancellationToken).ConfigureAwait(false);
                return new VeraCryptContainer(stream, fileSystem, lifetime, root, header.Algorithm, fsType);
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Searches every (<see cref="CryptoAlgorithm"/>, <see cref="HashAlgorithm"/>) combination
        /// against the container's primary header region, falling back to the backup region if none
        /// match, reading each region from disk only once regardless of how many combinations are
        /// tried.
        /// </summary>
        private static async Task<VeraCryptHeader> DetectHeaderAsync(FileInfo path, string password, int pim, IEnumerable<FileInfo> keyFiles, CancellationToken cancellationToken)
        {
            Stream stream;
            try
            {
                stream = path.OpenRead();
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is ArgumentNullException))
            {
                throw new InvalidOperationException($"Unable to open container file: {path.FullName}", ex);
            }

            using (stream)
            {
                var primaryRegion = await HeaderParser.ReadRegionAsync(stream, 0, HeaderParser.HeaderRegionSize, cancellationToken).ConfigureAwait(false);
                var header = await TryAllCombinationsAsync(primaryRegion, password, fromBackup: false, pim, keyFiles, cancellationToken).ConfigureAwait(false);
                if (header != null)
                {
                    return header;
                }

                if (stream.Length >= HeaderParser.BackupHeaderOffsetFromEnd)
                {
                    var backupOffset = stream.Length - HeaderParser.BackupHeaderOffsetFromEnd;
                    var backupRegion = await HeaderParser.ReadRegionAsync(stream, backupOffset, HeaderParser.HeaderRegionSize, cancellationToken).ConfigureAwait(false);
                    header = await TryAllCombinationsAsync(backupRegion, password, fromBackup: true, pim, keyFiles, cancellationToken).ConfigureAwait(false);
                    if (header != null)
                    {
                        return header;
                    }
                }
            }

            return null;
        }

        private static async Task<VeraCryptHeader> TryAllCombinationsAsync(byte[] region, string password, bool fromBackup, int pim, IEnumerable<FileInfo> keyFiles, CancellationToken cancellationToken)
        {
            foreach (CryptoAlgorithm algo in (CryptoAlgorithm[])Enum.GetValues(typeof(CryptoAlgorithm)))
            {
                foreach (HashAlgorithm hashAlgo in (HashAlgorithm[])Enum.GetValues(typeof(HashAlgorithm)))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var header = await HeaderParser.TryDecryptRegionAsync(region, password, algo, hashAlgo, fromBackup, pim, keyFiles, cancellationToken).ConfigureAwait(false);
                    if (header != null)
                    {
                        return header;
                    }
                }
            }
            return null;
        }

        private static readonly byte[] NtfsOemId = Encoding.ASCII.GetBytes("NTFS    ");
        private static readonly byte[] ExFatOemId = Encoding.ASCII.GetBytes("EXFAT   ");

        private const int BootSectorSize = 512;
        private const int BootSignatureOffset = 510;
        private const byte BootSignatureLowByte = 0x55;
        private const byte BootSignatureHighByte = 0xAA;

        /// <summary>
        /// Determines a decrypted volume's filesystem type by inspecting its boot sector directly,
        /// rather than trying to construct each DiscUtils filesystem type in turn. First confirms the
        /// standard 0x55 0xAA boot sector signature is present at the fixed offset 510-511 (this
        /// convention holds regardless of the volume's declared sector size), so that data which
        /// isn't a recognizable boot sector at all is rejected clearly and immediately, rather than
        /// silently falling through to FAT and surfacing a more roundabout error from
        /// <see cref="OpenFatAsync"/> once DiscUtils.Fat also fails to make sense of it. Then reads
        /// the OEM ID field (bytes 3-10): NTFS and exFAT both write a fixed, reliable OEM ID
        /// ("NTFS    " and "EXFAT   " respectively); FAT does not - it is free-form text set by
        /// whichever tool formatted the volume - so FAT is the default once NTFS and exFAT are ruled
        /// out. Confirmed empirically against all four test containers during the exFAT investigation.
        /// </summary>
        private static async Task<FileSystemType> DetectFileSystemTypeAsync(SectorDecryptor decryptor, CancellationToken cancellationToken)
        {
            var bootSector = await decryptor.ReadDecryptedAsync(0, BootSectorSize, cancellationToken).ConfigureAwait(false);

            if (bootSector[BootSignatureOffset] != BootSignatureLowByte || bootSector[BootSignatureOffset + 1] != BootSignatureHighByte)
            {
                throw new InvalidOperationException(
                    "The decrypted volume does not contain a recognizable boot sector. The password " +
                    "may be incorrect, or the container's filesystem is unsupported.");
            }

            var oemId = new byte[8];
            Buffer.BlockCopy(bootSector, 3, oemId, 0, 8);

            if (oemId.SequenceEqual(NtfsOemId))
            {
                return FileSystemType.Ntfs;
            }
            if (oemId.SequenceEqual(ExFatOemId))
            {
                return FileSystemType.ExFat;
            }
            return FileSystemType.Fat;
        }

        private static async Task<(DiscFileSystem fileSystem, IDirectory root)> OpenFileSystemAsync(
            FileSystemType fsType, DecryptedBlockDeviceStream stream, ContainerLifetime lifetime, CancellationToken cancellationToken)
        {
            switch (fsType)
            {
                case FileSystemType.Ntfs:
                    var ntfs = await OpenNtfsAsync(stream, cancellationToken).ConfigureAwait(false);
                    return (ntfs, new NtfsDirectory(ntfs, NtfsPathHelper.Root, lifetime));
                case FileSystemType.Fat:
                    var fat = await OpenFatAsync(stream, cancellationToken).ConfigureAwait(false);
                    return (fat, new FatDirectory(fat, FatPathHelper.Root, lifetime));
                case FileSystemType.ExFat:
                    var exFat = await OpenExFatAsync(stream, cancellationToken).ConfigureAwait(false);
                    return (exFat, new ExFatDirectory(exFat, ExFatPathHelper.Root, lifetime));
                default:
                    // Unreachable: fsType is either caller-validated (explicit-fsType OpenAsync) or
                    // computed by DetectFileSystemTypeAsync, which only ever returns a defined value.
                    throw new ArgumentException($"Unsupported filesystem type: {fsType}.", nameof(fsType));
            }
        }

        private static Task<NtfsFileSystem> OpenNtfsAsync(DecryptedBlockDeviceStream stream, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    return new NtfsFileSystem(stream);
                }
                catch (Exception ex) when (!(ex is ArgumentException || ex is ArgumentNullException))
                {
                    throw new InvalidOperationException("Failed to open the NTFS filesystem within the container.", ex);
                }
            }, cancellationToken);
        }

        private static Task<FatFileSystem> OpenFatAsync(DecryptedBlockDeviceStream stream, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                FatFileSystem fat;
                try
                {
                    fat = new FatFileSystem(stream);
                }
                catch (Exception ex) when (!(ex is ArgumentException || ex is ArgumentNullException))
                {
                    throw new InvalidOperationException("Failed to open the FAT filesystem within the container.", ex);
                }

                // The FAT16/FAT32 variant is a consequence of volume size, not a caller choice, so both
                // are accepted here. FatFileSystem's constructor does not strictly validate its input:
                // data that is not FAT at all (e.g. an NTFS volume) can still construct successfully,
                // typically misdetected as FatType.Fat12 or FatType.None, so those are rejected.
                if (fat.FatVariant != FatType.Fat16 && fat.FatVariant != FatType.Fat32)
                {
                    fat.Dispose();
                    throw new InvalidOperationException($"Expected a FAT16 or FAT32 filesystem but found {fat.FatVariant}.");
                }

                return fat;
            }, cancellationToken);
        }

        private static Task<ExFatFileSystem> OpenExFatAsync(DecryptedBlockDeviceStream stream, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    return new ExFatFileSystem(stream, ExFatPathHelper.PathSeparators);
                }
                catch (Exception ex) when (!(ex is ArgumentException || ex is ArgumentNullException))
                {
                    throw new InvalidOperationException("Failed to open the exFAT filesystem within the container.", ex);
                }
            }, cancellationToken);
        }


        /// <summary>
        /// The root directory of the container's decrypted filesystem.
        /// </summary>
        public IDirectory Root { get; private set; }

        /// <summary>
        /// The encryption algorithm the container was opened with - either as given to the
        /// explicit-parameters <see cref="OpenAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, FileSystemType, CancellationToken)"/>,
        /// or as detected by the password-only <see cref="OpenAsync(FileInfo, string, CancellationToken)"/>.
        /// </summary>
        public CryptoAlgorithm Algorithm { get; private set; }

        /// <summary>
        /// The filesystem type detected within the container - either as given to the
        /// explicit-parameters <see cref="OpenAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, FileSystemType, CancellationToken)"/>,
        /// or as detected by the password-only <see cref="OpenAsync(FileInfo, string, CancellationToken)"/>.
        /// </summary>
        public FileSystemType FileSystemType { get; private set; }


        /// <summary>
        /// Closes the container and releases the underlying filesystem and stream. Safe to call
        /// more than once: only the first call has any effect.
        /// </summary>
        public void Close()
        {
            // Deliberately idempotent by our own tracking, not by relying on the underlying
            // DiscFileSystem/Stream types' own Dispose() being safe to call twice: at least one
            // DiscUtils filesystem implementation is not (confirmed empirically to throw
            // NullReferenceException on a second Dispose() call).
            if (_lifetime.IsClosed)
            {
                return;
            }

            _lifetime.IsClosed = true;
            _fileSystem.Dispose();
            _stream.Dispose();
        }
    }
}
