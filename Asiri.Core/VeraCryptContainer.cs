using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils;
using DiscUtils.ExFat;
using DiscUtils.ExFat.Internal;
using DiscUtils.ExFat.Internal.Filesystem;
using DiscUtils.Fat;
using DiscUtils.Ntfs;
using DiscUtils.Partitions;
using DiscUtils.Vhd;
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
    /// The most permissive access to request when opening a VeraCrypt container - the ceiling for
    /// that session, not a live switch. See <see cref="VeraCryptContainer.IsWritable"/> for the
    /// separate, additional step actually required before any write is permitted even when
    /// <see cref="ReadWrite"/> is requested here.
    /// </summary>
    public enum ContainerAccessMode
    {
        /// <summary>
        /// The container can only be read. Opening with this mode - the default - can never be
        /// upgraded to <see cref="ReadWrite"/> later without closing and reopening the container.
        /// </summary>
        ReadOnly,

        /// <summary>
        /// The container's underlying file is opened for writing, and exclusively (no other process,
        /// or other Asiri container, can have it open at the same time) - but nothing can actually be
        /// written until <see cref="VeraCryptContainer.IsWritable"/> is also explicitly set to true.
        /// </summary>
        ReadWrite
    }

    /// <summary>
    /// The output format for <see cref="VeraCryptContainer.DumpRawImageAsync"/> - a diagnostic export
    /// of a container's decrypted filesystem, for handing to a tool, person, or AI session entirely
    /// outside Asiri (see that method's own remarks for why).
    /// </summary>
    public enum RawImageExportFormat
    {
        /// <summary>
        /// The whole decrypted filesystem, written as a bare sequence of bytes with no wrapper of any
        /// kind - exactly what DiscUtils formatted and reads from, nothing added or removed.
        /// </summary>
        RawImage,

        /// <summary>
        /// Only the first 512 bytes (the volume's boot sector) of the decrypted filesystem, as a bare
        /// sequence of bytes - a cheap way to eyeball just that, for the same reason
        /// <see cref="VeraCryptContainer.DetectFileSystemTypeAsync"/> only ever looks there itself.
        /// </summary>
        RawImageBootSectorOnly,

        /// <summary>
        /// The whole decrypted filesystem, wrapped in a fixed-size VHD with no partition table - a
        /// single, unpartitioned "superfloppy"-style virtual disk whose own first sector is the
        /// filesystem's boot sector, matching exactly how the filesystem is laid out inside the real
        /// encrypted container. Windows can mount a VHD natively (no VeraCrypt, no Asiri involved at
        /// all), which is the point: it lets the exported filesystem be tested for real-OS validity
        /// completely independently of everything else in Asiri's own pipeline.
        /// </summary>
        Vhd,

        /// <summary>
        /// The same idea as <see cref="Vhd"/>, but with a single MBR partition (of the appropriate
        /// type for the container's own <see cref="VeraCryptContainer.FileSystemType"/>) wrapped
        /// around the filesystem, rather than placing it directly at the start of the disk. Exists
        /// alongside <see cref="Vhd"/> specifically to separate two variables while diagnosing why a
        /// real OS doesn't recognise a container's filesystem: whether the filesystem's own content is
        /// at fault, or whether a partitioned-vs-unpartitioned disk layout is.
        /// </summary>
        VhdWithPartitionTable
    }


    /// <summary>
    /// Provides access to the contents of a VeraCrypt encrypted file container, read-only by default.
    /// </summary>
    /// <remarks>
    /// This code is pre-production: it has not undergone independent security review or a
    /// cryptographic audit. Writing to a container - opting into <see cref="ContainerAccessMode.ReadWrite"/>
    /// and then setting <see cref="IsWritable"/> - modifies the container file in place, with no
    /// undo. Only enable writing on a container you have a backup of.
    /// </remarks>
    public sealed class VeraCryptContainer
    {
        private readonly DecryptedBlockDeviceStream _stream;
        private readonly DiscFileSystem _fileSystem;
        private readonly ContainerLifetime _lifetime;

        private VeraCryptContainer(
            DecryptedBlockDeviceStream stream, DiscFileSystem fileSystem, ContainerLifetime lifetime, IDirectory root,
            CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, FileSystemType fileSystemType)
        {
            _stream = stream;
            _fileSystem = fileSystem;
            _lifetime = lifetime;
            Root = root;
            Algorithm = algorithm;
            HashAlgorithm = hashAlgorithm;
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
        /// <param name="accessMode">
        /// The most permissive access to open the container's underlying file with, or
        /// <see cref="ContainerAccessMode.ReadOnly"/> - the default - for read-only. Opening with
        /// <see cref="ContainerAccessMode.ReadWrite"/> does not by itself permit any write - see
        /// <see cref="IsWritable"/>, a separate, additional step - but it does take an exclusive lock
        /// on the file for the whole session, so only request it when you actually intend to write
        /// during this session, not defensively "just in case".
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
            ContainerAccessMode accessMode = ContainerAccessMode.ReadOnly,
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

            var canWrite = accessMode == ContainerAccessMode.ReadWrite;
            var header = await HeaderParser.ParseAsync(path, password, algo, hashAlgo, pim, keyFiles, cancellationToken).ConfigureAwait(false);
            var decryptor = await SectorDecryptor.CreateAsync(path, header, canWrite, cancellationToken).ConfigureAwait(false);
            var stream = new DecryptedBlockDeviceStream(decryptor);

            try
            {
                var lifetime = new ContainerLifetime { MaxAccessMode = accessMode };
                var (fileSystem, root) = await OpenFileSystemAsync(fsType, stream, lifetime, cancellationToken).ConfigureAwait(false);
                return new VeraCryptContainer(stream, fileSystem, lifetime, root, algo, hashAlgo, fsType);
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
        /// mounts a volume. Either or both of <paramref name="algo"/> and <paramref name="hashAlgo"/>
        /// can be supplied if already known, narrowing or eliminating the search accordingly.
        /// </summary>
        /// <remarks>
        /// An unspecified (algorithm, hash) combination cannot be known in advance: the only way to
        /// tell whether a combination is correct is to derive keys with it and check whether the
        /// header's CRC validates, so that pairing must genuinely be searched to whatever extent
        /// isn't already pinned down by <paramref name="algo"/>/<paramref name="hashAlgo"/>. This
        /// searches over <see cref="HeaderParser.TrySearchHashAlgorithmAsync"/> rather than looping
        /// <see cref="HeaderParser.ParseAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, int, IEnumerable{FileInfo}, CancellationToken)"/>
        /// directly, so the header regions are read from disk once and each combination is tried
        /// against the same bytes, rather than re-opening and re-reading the file per attempt.
        ///
        /// The filesystem type, by contrast, is never searched for, known or not: once the header
        /// decrypts correctly, the volume's boot sector can be read directly and its OEM ID signature
        /// inspected to determine NTFS, exFAT, or (by elimination) FAT - see
        /// <see cref="DetectFileSystemTypeAsync"/>. There is no equivalent "I already know the
        /// filesystem type" parameter here for that reason: there is no search cost on that axis to
        /// eliminate.
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
        /// <param name="algo">
        /// The container's encryption algorithm, if already known, or null - the default - to search
        /// every supported <see cref="CryptoAlgorithm"/>. Supplying this when known turns what would
        /// be up to 4 PBKDF2 derivations (one per hash algorithm still being searched) into exactly 1.
        /// </param>
        /// <param name="hashAlgo">
        /// The container's hash algorithm, if already known, or null - the default - to search every
        /// supported <see cref="HashAlgorithm"/>. Supplying this when known skips the (up to 3) other
        /// hash algorithms' derivations entirely, rather than only trying them after this one fails.
        /// </param>
        /// <param name="accessMode">
        /// The most permissive access to open the container's underlying file with - see the
        /// explicit-parameters overload's own remarks on this parameter.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A container whose <see cref="Root"/> exposes the decrypted filesystem.</returns>
        public static async Task<VeraCryptContainer> OpenAsync(
            FileInfo path,
            string password,
            int pim = 0,
            IEnumerable<FileInfo> keyFiles = null,
            CryptoAlgorithm? algo = null,
            HashAlgorithm? hashAlgo = null,
            ContainerAccessMode accessMode = ContainerAccessMode.ReadOnly,
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
            if (algo.HasValue && !CascadeDefinitions.IsSupported(algo.Value))
            {
                throw new ArgumentException($"Unsupported encryption algorithm: {algo.Value}.", nameof(algo));
            }
            if (hashAlgo.HasValue && !SupportedHashAlgorithms.Contains(hashAlgo.Value))
            {
                throw new ArgumentException($"Unsupported hash algorithm: {hashAlgo.Value}.", nameof(hashAlgo));
            }

            var header = await DetectHeaderAsync(path, password, pim, keyFiles, algo, hashAlgo, cancellationToken).ConfigureAwait(false);
            if (header == null)
            {
                throw new InvalidOperationException(
                    "Failed to decrypt the VeraCrypt volume header with any supported algorithm. " +
                    "The password may be incorrect, or the container may not be a valid VeraCrypt volume.");
            }

            var canWrite = accessMode == ContainerAccessMode.ReadWrite;
            var decryptor = await SectorDecryptor.CreateAsync(path, header, canWrite, cancellationToken).ConfigureAwait(false);
            var stream = new DecryptedBlockDeviceStream(decryptor);

            try
            {
                var fsType = await DetectFileSystemTypeAsync(decryptor, cancellationToken).ConfigureAwait(false);
                var lifetime = new ContainerLifetime { MaxAccessMode = accessMode };
                var (fileSystem, root) = await OpenFileSystemAsync(fsType, stream, lifetime, cancellationToken).ConfigureAwait(false);
                return new VeraCryptContainer(stream, fileSystem, lifetime, root, header.Algorithm, header.HashAlgorithm, fsType);
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }

        /// <summary>
        /// The sector size, in bytes, used for every container this creates. Matches VeraCrypt's own
        /// default for non-boot volumes, and every one of Asiri's own real-VeraCrypt-created test
        /// fixtures - not exposed as a caller choice, since there is no reason for Asiri itself to
        /// create a container with a different sector size.
        /// </summary>
        private const int DefaultSectorSize = 512;

        /// <summary>
        /// Creates a brand new VeraCrypt container file: a freshly formatted, empty filesystem,
        /// protected by a freshly generated master key, encrypted under the given credentials.
        /// </summary>
        /// <remarks>
        /// Verified against VeraCrypt's own source (Common/Format.c's <c>TCFormatVolume</c> and
        /// Common/Volumes.c's <c>CreateVolumeHeaderInMemory</c>), not assumed: <paramref name="size"/>
        /// is the container's TOTAL FILE SIZE, matching VeraCrypt's own creation-dialog convention -
        /// not the size of the filesystem inside it. VeraCrypt reserves a fixed 256 KiB of that for
        /// headers (see <see cref="HeaderParser.TotalHeaderOverheadSize"/>); the filesystem itself
        /// gets whatever remains. <paramref name="size"/> must exceed that overhead - by however much
        /// <paramref name="fileSystemType"/> itself needs on top, which this method does not attempt
        /// to duplicate: it lets the underlying DiscUtils formatter reject a too-small request on its
        /// own, wrapped in a clearer message, rather than replicating VeraCrypt's own per-filesystem
        /// minimum-size table.
        ///
        /// Returns an already-open container, but - exactly like
        /// <see cref="OpenAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, FileSystemType, int, IEnumerable{FileInfo}, ContainerAccessMode, CancellationToken)"/> -
        /// not yet writable: <see cref="IsWritable"/> must still be explicitly set to true before
        /// anything can be written to it, even though it was just created and starts out empty. This
        /// keeps "was this container just created" and "am I currently allowed to write to it"
        /// orthogonal, rather than special-casing creation.
        ///
        /// If any step fails after the container file has already been created on disk, that
        /// partially-written file is deleted, rather than left behind looking like a real container
        /// while actually being a corrupt, half-formed one.
        /// </remarks>
        /// <param name="path">Path to the new container file. Must not already exist.</param>
        /// <param name="size">The container's total file size, in bytes - see the remarks above.</param>
        /// <param name="password">The new container's password.</param>
        /// <param name="algorithm">The encryption algorithm to protect the container with.</param>
        /// <param name="hashAlgorithm">The hash algorithm to derive keys from the password with.</param>
        /// <param name="fileSystemType">The filesystem to format the container's data area with.</param>
        /// <param name="pim">The container's PIM (Personal Iterations Multiplier), or 0 for the default.</param>
        /// <param name="keyFiles">Keyfiles to mix into the password, in order, or null for none.</param>
        /// <param name="label">A volume label for the new filesystem, or null - the default - for none.</param>
        /// <param name="clusterSize">
        /// The filesystem's cluster size in bytes, or null - the default. Only meaningful for
        /// <see cref="FileSystemType.ExFat"/>: verified against DiscUtils' own source, its NTFS and
        /// FAT formatters give no way at all to override their own fixed (NTFS - always 4 KiB at this
        /// library's fixed 512-byte sector size) or size-derived (FAT) cluster size, so a non-null
        /// value here is rejected for either of those rather than silently ignored. When given, must
        /// be a positive power of two. For exFAT, null uses a fixed 4 KiB - matching NTFS's own
        /// cluster size, kept consistent across every filesystem type this method can produce - rather
        /// than exFAT's own size-tiered default (see <c>DefaultExFatClusterSize</c>).
        /// </param>
        /// <param name="cancellationToken">
        /// A token to cancel the operation. Honoured up until the container file is created on disk;
        /// not checked again during formatting, since a cancelled format would leave a corrupt file
        /// that this method would then need to clean up anyway - see the remarks above.
        /// </param>
        /// <returns>A container whose <see cref="Root"/> exposes the newly formatted, empty filesystem.</returns>
        public static Task<VeraCryptContainer> CreateAsync(
            FileInfo path,
            long size,
            string password,
            CryptoAlgorithm algorithm,
            HashAlgorithm hashAlgorithm,
            FileSystemType fileSystemType,
            int pim = 0,
            IEnumerable<FileInfo> keyFiles = null,
            string label = null,
            int? clusterSize = null,
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
            if (!CascadeDefinitions.IsSupported(algorithm))
            {
                throw new ArgumentException($"Unsupported encryption algorithm: {algorithm}.", nameof(algorithm));
            }
            if (!SupportedHashAlgorithms.Contains(hashAlgorithm))
            {
                throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}.", nameof(hashAlgorithm));
            }
            switch (fileSystemType)
            {
                case FileSystemType.Ntfs:
                case FileSystemType.Fat:
                case FileSystemType.ExFat:
                    break;
                default:
                    throw new ArgumentException($"Unsupported filesystem type: {fileSystemType}.", nameof(fileSystemType));
            }
            if (pim < 0)
            {
                throw new ArgumentException($"PIM must not be negative: {pim}.", nameof(pim));
            }
            if (size <= HeaderParser.TotalHeaderOverheadSize)
            {
                throw new ArgumentException(
                    $"Size must be greater than {HeaderParser.TotalHeaderOverheadSize} bytes (VeraCrypt's fixed " +
                    "header overhead), plus whatever the chosen filesystem itself needs on top.", nameof(size));
            }
            if (path.Exists)
            {
                throw new ArgumentException($"A file already exists at this path: {path.FullName}.", nameof(path));
            }
            if (clusterSize.HasValue)
            {
                if (fileSystemType != FileSystemType.ExFat)
                {
                    throw new ArgumentException(
                        $"A specific cluster size can only be requested for exFAT; DiscUtils' {fileSystemType} " +
                        "formatter provides no way to override its own cluster size.", nameof(clusterSize));
                }
                if (clusterSize.Value < DefaultSectorSize || (clusterSize.Value & (clusterSize.Value - 1)) != 0)
                {
                    throw new ArgumentException(
                        $"Cluster size must be a power of two of at least {DefaultSectorSize} bytes (this library's " +
                        $"fixed sector size): {clusterSize.Value}.", nameof(clusterSize));
                }
            }

            return CreateAsyncCore(path, size, password, algorithm, hashAlgorithm, fileSystemType, pim, keyFiles, label, clusterSize, cancellationToken);
        }

        private static async Task<VeraCryptContainer> CreateAsyncCore(
            FileInfo path, long size, string password, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm,
            FileSystemType fileSystemType, int pim, IEnumerable<FileInfo> keyFiles, string label, int? clusterSize, CancellationToken cancellationToken)
        {
            var dataAreaSize = size - HeaderParser.TotalHeaderOverheadSize;

            var (masterKey, secondaryKey) = HeaderParser.GenerateMasterKeys(algorithm);
            var plaintextHeader = HeaderParser.BuildNewHeaderPlaintext(dataAreaSize, DefaultSectorSize, masterKey, secondaryKey);

            // Each header location gets its own independent salt, matching ChangePasswordAsync and,
            // ultimately, VeraCrypt's own behaviour - it never writes the same encrypted bytes to both
            // header locations, even when the plaintext they encrypt is identical.
            var primaryRegion = await HeaderParser.BuildHeaderRegionAsync(
                plaintextHeader, algorithm, hashAlgorithm, password, pim, keyFiles, cancellationToken).ConfigureAwait(false);
            var backupRegion = await HeaderParser.BuildHeaderRegionAsync(
                plaintextHeader, algorithm, hashAlgorithm, password, pim, keyFiles, cancellationToken).ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await CreateContainerFileAsync(path, size, primaryRegion, backupRegion, cancellationToken).ConfigureAwait(false);
                // FileInfo caches Exists (and other metadata) as of when it was last queried -
                // SectorDecryptor.CreateAsync's own Exists check would otherwise still see the false
                // result path.Exists returned earlier in CreateAsync, before this method created the
                // file, and reject a container that genuinely exists on disk.
                path.Refresh();

                var header = new VeraCryptHeader
                {
                    Algorithm = algorithm,
                    HashAlgorithm = hashAlgorithm,
                    Magic = "VERA",
                    Version = 5,
                    HiddenVolumeSize = 0,
                    VolumeSize = dataAreaSize,
                    MasterKeyScopeOffset = HeaderParser.DataAreaOffset,
                    EncryptedAreaSize = dataAreaSize,
                    Flags = 0,
                    SectorSize = DefaultSectorSize,
                    MasterKey = masterKey,
                    SecondaryKey = secondaryKey,
                    CrcValid = true,
                    FromBackup = false,
                    DecryptedBytes = plaintextHeader
                };

                var decryptor = await SectorDecryptor.CreateAsync(path, header, canWrite: true, cancellationToken).ConfigureAwait(false);
                var stream = new DecryptedBlockDeviceStream(decryptor);

                try
                {
                    // Must happen before formatting, not after: a filesystem formatter only ever
                    // writes its own metadata (boot sector, MFT/FAT, root directory), never the free
                    // clusters it marks as unused, so anything already on disk under those clusters
                    // survives formatting untouched. Writing the random fill first, through this same
                    // encrypting stream, means even those never-written-by-the-formatter clusters end
                    // up holding real ciphertext - matching every genuine VeraCrypt volume - instead of
                    // the all-zero bytes CreateContainerFileAsync's own SetLength left behind.
                    await FillDataAreaWithRandomDataAsync(stream, cancellationToken).ConfigureAwait(false);

                    var lifetime = new ContainerLifetime { MaxAccessMode = ContainerAccessMode.ReadWrite };
                    var (fileSystem, root) = await FormatFileSystemAsync(fileSystemType, stream, dataAreaSize, label, clusterSize, lifetime, cancellationToken).ConfigureAwait(false);

                    // Physically flush the newly-formatted data area before handing the container
                    // back - see SectorDecryptor.FlushToDisk. The caller may hand this file straight
                    // to another process (e.g. mounting it in real VeraCrypt) the moment this returns,
                    // and that process's own I/O can bypass the cache this data area's writes would
                    // otherwise still only be sitting in.
                    await Task.Run(() => stream.FlushToDisk(), cancellationToken).ConfigureAwait(false);

                    return new VeraCryptContainer(stream, fileSystem, lifetime, root, algorithm, hashAlgorithm, fileSystemType);
                }
                catch
                {
                    stream.Dispose();
                    throw;
                }
            }
            catch
            {
                TryDeleteFile(path);
                throw;
            }
        }

        private static Task CreateContainerFileAsync(FileInfo path, long size, byte[] primaryRegion, byte[] backupRegion, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                FileStream stream;
                try
                {
                    // FileMode.CreateNew - rather than the already-performed path.Exists check alone -
                    // closes the race between that check and this call: it throws if another process
                    // (or another call into this method) created the file in the meantime.
                    stream = path.Open(FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
                }
                catch (Exception ex) when (!(ex is ArgumentException || ex is ArgumentNullException))
                {
                    throw new InvalidOperationException($"Unable to create container file: {path.FullName}", ex);
                }

                using (stream)
                {
                    stream.SetLength(size);

                    stream.Seek(0, SeekOrigin.Begin);
                    stream.Write(primaryRegion, 0, primaryRegion.Length);
                    FillWithRandomData(stream, HeaderParser.HeaderRegionSize, UnusedHeaderRegionSize);

                    var backupRegionOffset = size - HeaderParser.BackupHeaderOffsetFromEnd;
                    stream.Seek(backupRegionOffset, SeekOrigin.Begin);
                    stream.Write(backupRegion, 0, backupRegion.Length);
                    FillWithRandomData(stream, backupRegionOffset + HeaderParser.HeaderRegionSize, UnusedHeaderRegionSize);

                    // Flush(true), not the parameterless overload - a real, physical flush, not just a
                    // push into the OS's own shared cache. See SectorDecryptor.FlushToDisk for why:
                    // VeraCrypt's own driver opens a file-hosted container with cache-bypassing,
                    // unbuffered I/O for a standard 512-byte-sector host disk, so anything short of a
                    // physical flush here leaves a real window where these header regions look stale
                    // (or unwritten) to VeraCrypt itself, moments after this method returns.
                    stream.Flush(true);
                }
            }, cancellationToken);
        }

        /// <summary>
        /// The size, in bytes, of the "unused" space between the end of a 512-byte encrypted header
        /// region and the start of whatever follows it - the data area, for the primary header; the
        /// end of the file, for the backup header. This is where a hidden volume's own header would
        /// live if one existed - see <see cref="FillWithRandomData"/> for why it matters that this
        /// space is never left as zero.
        /// </summary>
        private const long UnusedHeaderRegionSize = HeaderParser.DataAreaOffset - HeaderParser.HeaderRegionSize;

        /// <summary>
        /// Fills a byte range with cryptographically random data. Verified against VeraCrypt's own
        /// Volume Format Specification: every byte of a genuine VeraCrypt volume that isn't actually
        /// in use - specifically the space between each 512-byte header region and the area where a
        /// hidden volume's own header could reside, on both the primary and backup sides - is
        /// indistinguishable from random noise in every real VeraCrypt-created volume, precisely so an
        /// observer can never tell whether that space holds a hidden volume or nothing at all
        /// (plausible deniability). <see cref="CreateContainerFileAsync"/> previously left this space
        /// as zero, courtesy of <see cref="Stream.SetLength"/>'s own zero-fill on a newly extended
        /// file - a real, spec-verified deviation from every genuine VeraCrypt volume, including this
        /// project's own real-VeraCrypt-created test fixtures, which this method now closes.
        /// </summary>
        private static void FillWithRandomData(Stream stream, long offset, long length)
        {
            var buffer = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }

            stream.Seek(offset, SeekOrigin.Begin);
            stream.Write(buffer, 0, buffer.Length);
        }

        /// <summary>
        /// The chunk size used by <see cref="FillDataAreaWithRandomDataAsync"/>. Kept well below the
        /// smallest containers this library is likely to create so the whole data area is never
        /// buffered in memory at once (see Asiri.Core's own "do not load the entire container into
        /// memory" requirement), while still being large enough to keep per-write overhead low for
        /// realistically-sized containers.
        /// </summary>
        private const int DataAreaRandomFillChunkSize = 1024 * 1024;

        /// <summary>
        /// Fills the entire data area with cryptographically random plaintext, encrypted through
        /// <paramref name="stream"/> exactly like any other write. Verified against VeraCrypt's own
        /// Volume Format Specification: "free space on each VeraCrypt volume is filled with random
        /// data when the volume is created", generated by encrypting random plaintext blocks and
        /// writing the resulting ciphertext across the volume "right before volume formatting
        /// begins" - i.e. the whole data area, not just whatever a filesystem formatter happens to
        /// touch. Must run before <see cref="FormatFileSystemAsync"/> for that reason: formatting
        /// only ever writes its own metadata, never the free clusters it marks unused, so this fill
        /// is the only thing that ever reaches those bytes. Fills exactly <paramref name="stream"/>'s
        /// own <see cref="Stream.Length"/> - which the stream itself derives from a whole number of
        /// sectors - rather than the caller-specified data-area size verbatim, since that can include
        /// a handful of trailing bytes short of a full sector that the stream never exposes as
        /// writable at all.
        /// </summary>
        private static Task FillDataAreaWithRandomDataAsync(DecryptedBlockDeviceStream stream, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                stream.Seek(0, SeekOrigin.Begin);
                using (var rng = RandomNumberGenerator.Create())
                {
                    var buffer = new byte[Math.Min(DataAreaRandomFillChunkSize, stream.Length)];
                    var remaining = stream.Length;
                    while (remaining > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var chunkSize = (int)Math.Min(buffer.Length, remaining);
                        rng.GetBytes(buffer);
                        stream.Write(buffer, 0, chunkSize);
                        remaining -= chunkSize;
                    }
                }

                // Leave the stream positioned where FormatFileSystemAsync's own formatters expect to
                // start writing from - this fill otherwise leaves it at the end of the data area.
                stream.Seek(0, SeekOrigin.Begin);
            }, cancellationToken);
        }

        private static void TryDeleteFile(FileInfo path)
        {
            try
            {
                path.Refresh();
                if (path.Exists)
                {
                    path.Delete();
                }
            }
            catch
            {
                // Best-effort cleanup only - the exception from whatever step actually failed is what
                // the caller needs to see, not a secondary failure from trying to delete the file.
            }
        }

        private static Task<(DiscFileSystem fileSystem, IDirectory root)> FormatFileSystemAsync(
            FileSystemType fsType, DecryptedBlockDeviceStream stream, long dataAreaSize, string label, int? clusterSize, ContainerLifetime lifetime, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    (DiscFileSystem fileSystem, IDirectory root) result;
                    switch (fsType)
                    {
                        case FileSystemType.Ntfs:
                            result = FormatNtfs(stream, dataAreaSize, label, lifetime);
                            break;
                        case FileSystemType.Fat:
                            result = FormatFat(stream, dataAreaSize, label, lifetime);
                            break;
                        case FileSystemType.ExFat:
                            result = FormatExFat(stream, label, clusterSize, lifetime);
                            break;
                        default:
                            // Unreachable: fsType is already caller-validated by CreateAsync.
                            throw new ArgumentException($"Unsupported filesystem type: {fsType}.", nameof(fsType));
                    }

                    // None of DiscUtils' own from-scratch Format methods write the standard PC boot-
                    // sector signature (0x55 0xAA at bytes 510-511 of the volume's first sector) -
                    // nothing internal to DiscUtils itself checks for it, so its own formatters simply
                    // never set it. Every genuine FAT/NTFS/exFAT volume carries it - confirmed
                    // empirically against real VeraCrypt-created fixtures, see
                    // DetectFileSystemTypeAsync's own remarks - and without it, real Windows refuses
                    // to recognise the volume at all (confirmed: a container this method created
                    // mounted successfully in real VeraCrypt - the encryption itself was never the
                    // problem - but Explorer could not read its contents), and neither would Asiri's
                    // own password-only auto-detecting OpenAsync, which checks for exactly this.
                    stream.Seek(BootSignatureOffset, SeekOrigin.Begin);
                    stream.Write(new[] { BootSignatureLowByte, BootSignatureHighByte }, 0, 2);

                    return result;
                }
                catch (Exception ex) when (!(ex is OperationCanceledException))
                {
                    // Unlike OpenNtfsAsync/OpenFatAsync/OpenExFatAsync, an ArgumentException here is
                    // never Asiri's OWN upstream parameter validation (that already happened, in
                    // CreateAsync, before this was ever called) - it can only be DiscUtils' own
                    // formatter rejecting the request (e.g. FatFileSystem.FormatPartition's "too small
                    // for a partition") or the size-too-large check in FormatFat below, so both are
                    // wrapped uniformly for a clearer message, rather than let through raw.
                    throw new InvalidOperationException($"Failed to format a {fsType} filesystem within the container.", ex);
                }
            }, cancellationToken);
        }

        private static (DiscFileSystem fileSystem, IDirectory root) FormatNtfs(DecryptedBlockDeviceStream stream, long dataAreaSize, string label, ContainerLifetime lifetime)
        {
            var sectorCount = dataAreaSize / DefaultSectorSize;
            var geometry = Geometry.FromCapacity(dataAreaSize, DefaultSectorSize);
            var ntfs = NtfsFileSystem.Format(stream, label, geometry, firstSector: 0, sectorCount);

            // The 5-argument Format() overload above - the only one that doesn't ask the caller to
            // separately construct a full NtfsFormatOptions or hand-build a real x86 bootstrap - leaves
            // the boot sector's first 3 bytes zero rather than a valid jump instruction. Confirmed
            // independently (not just against Asiri's own read path): libmagic's `file` correctly
            // identified a real VeraCrypt-created NTFS fixture in full detail down to its $MFT start
            // cluster, but only ever reported a container formatted this way as a generic "DOS/MBR
            // boot sector" - never specifically NTFS - until this was added. FAT's and exFAT's own
            // DiscUtils formatters already write a correct jump themselves (confirmed the same way);
            // this gap is NTFS-specific. EB 52 90 matches the exact bytes real VeraCrypt/Windows uses
            // in every one of this project's own real NTFS test fixtures - a short jump to offset 0x52
            // (which is also where DiscUtils' own NtfsFormatter's non-bootstrap BPB fields end) plus a
            // NOP - not functional boot code, since nothing ever actually boots a VeraCrypt container,
            // just bytes that look like a genuine one to whatever validates that they do.
            stream.Seek(0, SeekOrigin.Begin);
            stream.Write(new byte[] { 0xEB, 0x52, 0x90 }, 0, 3);

            return (ntfs, new NtfsDirectory(ntfs, NtfsPathHelper.Root, lifetime));
        }

        private static (DiscFileSystem fileSystem, IDirectory root) FormatFat(DecryptedBlockDeviceStream stream, long dataAreaSize, string label, ContainerLifetime lifetime)
        {
            var sectorCount = dataAreaSize / DefaultSectorSize;
            if (sectorCount > int.MaxValue)
            {
                throw new ArgumentException(
                    $"The requested size is too large for a FAT filesystem via this library (data area over " +
                    $"{(long)int.MaxValue * DefaultSectorSize} bytes). Use NTFS or exFAT instead.");
            }

            var geometry = Geometry.FromCapacity(dataAreaSize, DefaultSectorSize);
            var fat = FatFileSystem.FormatPartition(stream, label, geometry, firstSector: 0, sectorCount: (int)sectorCount, reservedSectors: 0);
            return (fat, new FatDirectory(fat, FatPathHelper.Root, lifetime));
        }

        /// <summary>
        /// The cluster size used for a new exFAT filesystem when the caller doesn't request one -
        /// 4 KiB, matching NTFS's own fixed cluster size (see FormatNtfs) rather than deferring to
        /// ExFatPartition.Format's own size-tiered default (4 KiB up to 256 MiB, 32 KiB up to 32 GiB,
        /// 128 KiB beyond that). An explicit, known value here keeps cluster size consistent across
        /// every filesystem type CreateAsync can produce, rather than one that silently varies with
        /// volume size for exFAT alone.
        /// </summary>
        private const int DefaultExFatClusterSize = 4096;

        private static (DiscFileSystem fileSystem, IDirectory root) FormatExFat(DecryptedBlockDeviceStream stream, string label, int? clusterSize, ContainerLifetime lifetime)
        {
            var effectiveClusterSize = clusterSize ?? DefaultExFatClusterSize;
            var options = new ExFatFormatOptions { SectorsPerCluster = (uint)(effectiveClusterSize / DefaultSectorSize) };

            // ExFatPathFilesystem.Format returns a transient wrapper needed only while writing the new
            // filesystem's metadata - it must be disposed (flushing it) before the same stream can be
            // reopened as a normal ExFatFileSystem, exactly matching DiscUtils' own
            // ExFatFileSystem.Format(PhysicalVolumeInfo, ...) convenience wrapper, which does the same
            // two-step dance internally.
            using (ExFatPathFilesystem.Format(stream, options, label))
            {
            }

            var exFat = new ExFatFileSystem(stream, ExFatPathHelper.PathSeparators);
            return (exFat, new ExFatDirectory(exFat, ExFatPathHelper.Root, lifetime));
        }

        /// <summary>
        /// Changes a container's password, keyfiles, PIM, and/or hash algorithm, without touching
        /// its contents. Verified against VeraCrypt's own source (Common/Password.c's
        /// <c>ChangePwd</c>), not just its documentation: the volume's master and secondary keys -
        /// the only things that actually protect its data - are never changed by this operation,
        /// only the header's own encryption key (re-derived from the new credentials with a fresh
        /// random salt) is. Static, and does not require the container to already be open: this
        /// never touches the filesystem region at all, so mounting one first via
        /// <see cref="OpenAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, FileSystemType, int, IEnumerable{FileInfo}, ContainerAccessMode, CancellationToken)"/>
        /// would be pure wasted work.
        /// </summary>
        /// <remarks>
        /// Rewrites the primary header first, then the backup header, each with its own independent
        /// fresh salt (matching VeraCrypt's own behaviour - it does not write the same bytes to both
        /// locations). If the process is interrupted between the two writes, the container is still
        /// openable - with the *old* credentials, via the automatic backup-header fallback
        /// <see cref="HeaderParser.ParseAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, int, IEnumerable{FileInfo}, CancellationToken)"/>
        /// already provides - since the backup hasn't been touched yet. That's an inherent property
        /// of VeraCrypt's fixed two-copies format, not something this method can improve on while
        /// staying format-compatible; if the backup write itself fails, the resulting exception says
        /// so explicitly, since at that point the primary has already changed but the backup hasn't.
        ///
        /// Both new header regions are self-verified before either is written: decrypted and
        /// validated with the new credentials, and checked to still carry the exact same
        /// master/secondary key as the original, entirely in memory. VeraCrypt's own C implementation
        /// doesn't need this (it's mature, long-tested code); this one is new, so the extra check
        /// costs little and catches a bug in this method itself before it can ever reach disk.
        ///
        /// Unlike real VeraCrypt, this does not perform its optional multi-pass anti-forensic
        /// overwrite of the old header location (each pass a genuinely valid header, just with a
        /// different random salt, intended to make recovering the old header via magnetic/flash
        /// remanence harder) - a deliberate scope decision, not an oversight: it is a defense-in-depth
        /// measure, not required for correctness.
        /// </remarks>
        /// <param name="path">Path to the VeraCrypt container file.</param>
        /// <param name="oldPassword">The container's current password.</param>
        /// <param name="algorithm">
        /// The container's encryption algorithm. Unlike every other credential here, this cannot
        /// change: VeraCrypt itself never lets a password/keyfile change also change the cipher,
        /// since that would require re-encrypting the entire data area, not just the header.
        /// </param>
        /// <param name="oldHashAlgorithm">The current hash algorithm used to derive keys from the password.</param>
        /// <param name="oldPim">The container's current PIM, or 0 if it uses the default.</param>
        /// <param name="oldKeyFiles">The container's current keyfiles, in order, or null for none.</param>
        /// <param name="newPassword">The new password.</param>
        /// <param name="newPim">
        /// The new PIM, or 0 for the default - not "keep the old one": VeraCrypt itself always
        /// requires this to be stated explicitly for the new credentials, the same way
        /// <see cref="OpenAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, FileSystemType, int, IEnumerable{FileInfo}, ContainerAccessMode, CancellationToken)"/>'s
        /// own <c>pim</c> parameter does.
        /// </param>
        /// <param name="newKeyFiles">The new keyfiles, in order, or null for none.</param>
        /// <param name="newHashAlgorithm">
        /// The new hash algorithm, or null - the default - to keep <paramref name="oldHashAlgorithm"/>
        /// unchanged. VeraCrypt itself allows the hash algorithm to change independently of the
        /// password.
        /// </param>
        /// <param name="cancellationToken">
        /// A token to cancel the operation. Honoured up until the point the first byte is written to
        /// disk; not checked again between the primary and backup writes, to keep that already-inherent
        /// window as short as possible rather than artificially widening it.
        /// </param>
        public static async Task ChangePasswordAsync(
            FileInfo path,
            string oldPassword, CryptoAlgorithm algorithm, HashAlgorithm oldHashAlgorithm, int oldPim, IEnumerable<FileInfo> oldKeyFiles,
            string newPassword, int newPim, IEnumerable<FileInfo> newKeyFiles, HashAlgorithm? newHashAlgorithm = null,
            CancellationToken cancellationToken = default)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }
            if (oldPassword == null)
            {
                throw new ArgumentNullException(nameof(oldPassword));
            }
            if (newPassword == null)
            {
                throw new ArgumentNullException(nameof(newPassword));
            }
            if (!CascadeDefinitions.IsSupported(algorithm))
            {
                throw new ArgumentException($"Unsupported encryption algorithm: {algorithm}.", nameof(algorithm));
            }
            if (!SupportedHashAlgorithms.Contains(oldHashAlgorithm))
            {
                throw new ArgumentException($"Unsupported hash algorithm: {oldHashAlgorithm}.", nameof(oldHashAlgorithm));
            }
            if (newHashAlgorithm.HasValue && !SupportedHashAlgorithms.Contains(newHashAlgorithm.Value))
            {
                throw new ArgumentException($"Unsupported hash algorithm: {newHashAlgorithm.Value}.", nameof(newHashAlgorithm));
            }
            if (oldPim < 0)
            {
                throw new ArgumentException($"PIM must not be negative: {oldPim}.", nameof(oldPim));
            }
            if (newPim < 0)
            {
                throw new ArgumentException($"PIM must not be negative: {newPim}.", nameof(newPim));
            }

            var effectiveNewHashAlgorithm = newHashAlgorithm ?? oldHashAlgorithm;

            // Reading and validating the OLD header, with the OLD credentials, is both how we obtain
            // the master/secondary key and the ONLY proof that the caller actually knows the current
            // credentials - never skip or weaken this to get here faster.
            var oldHeader = await HeaderParser.ParseAsync(path, oldPassword, algorithm, oldHashAlgorithm, oldPim, oldKeyFiles, cancellationToken).ConfigureAwait(false);

            var newPrimaryRegion = await HeaderParser.BuildHeaderRegionAsync(
                oldHeader.DecryptedBytes, algorithm, effectiveNewHashAlgorithm, newPassword, newPim, newKeyFiles, cancellationToken).ConfigureAwait(false);
            await SelfVerifyAsync(oldHeader, newPrimaryRegion, algorithm, effectiveNewHashAlgorithm, newPassword, newPim, newKeyFiles, fromBackup: false, cancellationToken).ConfigureAwait(false);

            var newBackupRegion = await HeaderParser.BuildHeaderRegionAsync(
                oldHeader.DecryptedBytes, algorithm, effectiveNewHashAlgorithm, newPassword, newPim, newKeyFiles, cancellationToken).ConfigureAwait(false);
            await SelfVerifyAsync(oldHeader, newBackupRegion, algorithm, effectiveNewHashAlgorithm, newPassword, newPim, newKeyFiles, fromBackup: true, cancellationToken).ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            FileStream fileStream;
            try
            {
                fileStream = path.Open(FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is ArgumentNullException))
            {
                throw new InvalidOperationException($"Unable to open container file for writing: {path.FullName}", ex);
            }

            using (fileStream)
            {
                // Primary first, then backup: if this is interrupted in between, the container is
                // still openable with the OLD credentials via automatic backup-header fallback, since
                // the backup hasn't been touched yet. CancellationToken.None from here on - see the
                // remarks on honouring cancellation only up to this point.
                // Flush(true) throughout, not the parameterless overload - see
                // SectorDecryptor.FlushToDisk: a physical flush, not just a push into the OS's own
                // shared cache, matching how VeraCrypt's own driver can read this file with
                // cache-bypassing, unbuffered I/O.
                await HeaderParser.WriteRegionAsync(fileStream, 0, newPrimaryRegion, CancellationToken.None).ConfigureAwait(false);
                fileStream.Flush(true);

                var backupOffset = fileStream.Length - HeaderParser.BackupHeaderOffsetFromEnd;
                try
                {
                    await HeaderParser.WriteRegionAsync(fileStream, backupOffset, newBackupRegion, CancellationToken.None).ConfigureAwait(false);
                    fileStream.Flush(true);
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException(
                        "The primary header was rewritten with the new credentials, but writing the backup " +
                        "header failed. The container is still fully openable with the NEW credentials (the " +
                        "primary header succeeded); the backup header still reflects the OLD credentials " +
                        "until this is retried.", ex);
                }
            }
        }

        /// <summary>
        /// Confirms a newly built header region actually decrypts back to a valid header, with the
        /// new credentials, that carries the exact same master and secondary key as the original -
        /// entirely in memory, before <see cref="ChangePasswordAsync"/> writes anything to disk.
        /// </summary>
        private static async Task SelfVerifyAsync(
            VeraCryptHeader oldHeader, byte[] newRegion, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm,
            string password, int pim, IEnumerable<FileInfo> keyFiles, bool fromBackup, CancellationToken cancellationToken)
        {
            var verified = await HeaderParser.TryDecryptRegionAsync(newRegion, password, algorithm, hashAlgorithm, fromBackup, pim, keyFiles, cancellationToken).ConfigureAwait(false);
            if (verified == null || !verified.MasterKey.SequenceEqual(oldHeader.MasterKey) || !verified.SecondaryKey.SequenceEqual(oldHeader.SecondaryKey))
            {
                throw new InvalidOperationException(
                    "Internal error: the newly built header region failed to self-verify. Nothing has been written to the container file.");
            }
        }

        /// <summary>
        /// Searches every (<see cref="CryptoAlgorithm"/>, <see cref="HashAlgorithm"/>) combination
        /// against the container's primary header region, falling back to the backup region if none
        /// match, reading each region from disk only once regardless of how many combinations are
        /// tried.
        /// </summary>
        private static async Task<VeraCryptHeader> DetectHeaderAsync(
            FileInfo path, string password, int pim, IEnumerable<FileInfo> keyFiles,
            CryptoAlgorithm? algo, HashAlgorithm? hashAlgo, CancellationToken cancellationToken)
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

            // Mixing keyfiles into the password only depends on the password and keyfiles, not on
            // which (algorithm, hash) combination or header region is being tried, so it is done once
            // here rather than once per combination (up to 80 times: 40 combinations x primary and
            // backup regions) as it would be if this delegated to HeaderParser.TryDecryptRegionAsync.
            var passwordBytes = KeyfileMixer.Apply(Encoding.UTF8.GetBytes(password), keyFiles);

            using (stream)
            {
                var primaryRegion = await HeaderParser.ReadRegionAsync(stream, 0, HeaderParser.HeaderRegionSize, cancellationToken).ConfigureAwait(false);
                var header = await TryAllCombinationsAsync(primaryRegion, passwordBytes, fromBackup: false, pim, algo, hashAlgo, cancellationToken).ConfigureAwait(false);
                if (header != null)
                {
                    return header;
                }

                if (stream.Length >= HeaderParser.BackupHeaderOffsetFromEnd)
                {
                    var backupOffset = stream.Length - HeaderParser.BackupHeaderOffsetFromEnd;
                    var backupRegion = await HeaderParser.ReadRegionAsync(stream, backupOffset, HeaderParser.HeaderRegionSize, cancellationToken).ConfigureAwait(false);
                    header = await TryAllCombinationsAsync(backupRegion, passwordBytes, fromBackup: true, pim, algo, hashAlgo, cancellationToken).ConfigureAwait(false);
                    if (header != null)
                    {
                        return header;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Every supported <see cref="CryptoAlgorithm"/>, ordered so single-cipher algorithms (the
        /// least key material to derive) are tried before cascades. <see cref="TryAllCombinationsAsync"/>
        /// tries them in this order for each hash algorithm so that
        /// <see cref="HeaderParser.TrySearchHashAlgorithmAsync"/>'s incremental key derivation grows
        /// only as far as actually needed: a single-cipher container is found without ever deriving
        /// cascade-sized key material.
        /// </summary>
        private static readonly CryptoAlgorithm[] AlgorithmsByAscendingComponentCount =
            ((CryptoAlgorithm[])Enum.GetValues(typeof(CryptoAlgorithm)))
                .OrderBy(CascadeDefinitions.GetComponentCount)
                .ToArray();

        /// <summary>
        /// Every <see cref="HashAlgorithm"/> this library supports, in the order
        /// <see cref="TryAllCombinationsAsync"/> tries them when the caller hasn't already narrowed
        /// it down via <see cref="OpenAsync(FileInfo, string, int, IEnumerable{FileInfo}, CryptoAlgorithm?, HashAlgorithm?, ContainerAccessMode, CancellationToken)"/>'s
        /// <c>hashAlgo</c> parameter. Also doubles as the validation set for that parameter - see
        /// <c>SupportedHashAlgorithms.Contains</c> in <c>OpenAsync</c> above.
        /// </summary>
        private static readonly HashAlgorithm[] SupportedHashAlgorithms = (HashAlgorithm[])Enum.GetValues(typeof(HashAlgorithm));

        /// <summary>
        /// Searches every (<see cref="CryptoAlgorithm"/>, <see cref="HashAlgorithm"/>) combination not
        /// already ruled out by <paramref name="algo"/>/<paramref name="hashAlgo"/> - each narrows the
        /// corresponding axis to a single value instead of searching it, rather than changing how the
        /// search itself works. When both are supplied this still goes through the same brute-force
        /// scaffolding (reading header regions, mixing keyfiles) as a single, one-combination search,
        /// rather than <see cref="HeaderParser.ParseAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, int, IEnumerable{FileInfo}, CancellationToken)"/>'s
        /// more direct path - a caller with full knowledge of both should prefer the fully-explicit
        /// <see cref="OpenAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, FileSystemType, int, IEnumerable{FileInfo}, ContainerAccessMode, CancellationToken)"/>
        /// overload instead, which also skips filesystem-type detection.
        /// </summary>
        private static async Task<VeraCryptHeader> TryAllCombinationsAsync(
            byte[] region, byte[] passwordBytes, bool fromBackup, int pim,
            CryptoAlgorithm? algo, HashAlgorithm? hashAlgo, CancellationToken cancellationToken)
        {
            var algorithmsToTry = algo.HasValue ? new[] { algo.Value } : AlgorithmsByAscendingComponentCount;
            var hashAlgorithmsToTry = hashAlgo.HasValue ? new[] { hashAlgo.Value } : SupportedHashAlgorithms;

            foreach (var candidateHashAlgo in hashAlgorithmsToTry)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var header = await HeaderParser.TrySearchHashAlgorithmAsync(
                    region, passwordBytes, candidateHashAlgo, algorithmsToTry, fromBackup, pim, cancellationToken).ConfigureAwait(false);
                if (header != null)
                {
                    return header;
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
        /// explicit-parameters <see cref="OpenAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, FileSystemType, int, IEnumerable{FileInfo}, ContainerAccessMode, CancellationToken)"/>,
        /// or as detected by the password-only <see cref="OpenAsync(FileInfo, string, int, IEnumerable{FileInfo}, CryptoAlgorithm?, HashAlgorithm?, ContainerAccessMode, CancellationToken)"/>.
        /// </summary>
        public CryptoAlgorithm Algorithm { get; private set; }

        /// <summary>
        /// The hash algorithm the container was opened with - either as given to the
        /// explicit-parameters <see cref="OpenAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, FileSystemType, int, IEnumerable{FileInfo}, ContainerAccessMode, CancellationToken)"/>,
        /// or as detected by the password-only <see cref="OpenAsync(FileInfo, string, int, IEnumerable{FileInfo}, CryptoAlgorithm?, HashAlgorithm?, ContainerAccessMode, CancellationToken)"/>.
        /// </summary>
        public HashAlgorithm HashAlgorithm { get; private set; }

        /// <summary>
        /// The filesystem type detected within the container - either as given to the
        /// explicit-parameters <see cref="OpenAsync(FileInfo, string, CryptoAlgorithm, HashAlgorithm, FileSystemType, int, IEnumerable{FileInfo}, ContainerAccessMode, CancellationToken)"/>,
        /// or as detected by the password-only <see cref="OpenAsync(FileInfo, string, int, IEnumerable{FileInfo}, CryptoAlgorithm?, HashAlgorithm?, ContainerAccessMode, CancellationToken)"/>.
        /// </summary>
        public FileSystemType FileSystemType { get; private set; }

        /// <summary>
        /// Whether writing is currently armed. Starts false even when this container was opened with
        /// <see cref="ContainerAccessMode.ReadWrite"/> - opening for write access and actually
        /// permitting a write are two separate, both-required steps, deliberately: an errant code
        /// path that opens a container read-write when it shouldn't have still can't write anything
        /// without this also being set. Every mutating <see cref="IFile"/>/<see cref="IDirectory"/>
        /// call checks this at the moment it's made (or, for <see cref="IFile.OpenWriteAsync"/>, at
        /// the moment the write stream is opened) - not continuously for the lifetime of an
        /// already-open write stream, so setting this false does not retroactively stop a write
        /// already in progress through a stream obtained earlier.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Thrown when setting this true if the container was opened with
        /// <see cref="ContainerAccessMode.ReadOnly"/>: that ceiling can only be raised by closing and
        /// reopening the container with <see cref="ContainerAccessMode.ReadWrite"/>, never at runtime.
        /// </exception>
        public bool IsWritable
        {
            get => _lifetime.IsWritable;
            set
            {
                _lifetime.ThrowIfClosed();
                if (value && _lifetime.MaxAccessMode != ContainerAccessMode.ReadWrite)
                {
                    throw new InvalidOperationException(
                        "Cannot enable writing: this container was opened with ContainerAccessMode.ReadOnly. " +
                        "Close it and reopen with ContainerAccessMode.ReadWrite instead.");
                }
                _lifetime.IsWritable = value;
            }
        }

        /// <summary>
        /// The size, in bytes, of the container's decrypted filesystem - its encrypted data area,
        /// i.e. <see cref="HeaderParser.TotalHeaderOverheadSize"/> less than the container's own total
        /// file size. What <see cref="DumpRawImageAsync"/> writes for <see cref="RawImageExportFormat.RawImage"/>.
        /// </summary>
        public long FileSystemSizeInBytes
        {
            get
            {
                _lifetime.ThrowIfClosed();
                return _stream.Length;
            }
        }

        /// <summary>
        /// Exports the container's decrypted filesystem to <paramref name="destination"/>, in the
        /// given <paramref name="format"/> - none of it encrypted, and none of it interpreted by
        /// Asiri or DiscUtils on the way out. Added specifically to let that plaintext be handed to
        /// tools, reviewers, or a real OS's own mount path entirely outside Asiri, to help pin down
        /// why a container this library creates isn't recognised by a real OS - a question Asiri's
        /// own read path, which agrees with itself by construction, can't answer on its own.
        /// </summary>
        /// <param name="destination">
        /// The stream to write the export to. Written to starting at its current position; never
        /// sought or resized by this method.
        /// </param>
        /// <param name="format">The export format - see <see cref="RawImageExportFormat"/>.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        public Task DumpRawImageAsync(Stream destination, RawImageExportFormat format = RawImageExportFormat.RawImage, CancellationToken cancellationToken = default)
        {
            if (destination == null)
            {
                throw new ArgumentNullException(nameof(destination));
            }
            switch (format)
            {
                case RawImageExportFormat.RawImage:
                case RawImageExportFormat.RawImageBootSectorOnly:
                case RawImageExportFormat.Vhd:
                case RawImageExportFormat.VhdWithPartitionTable:
                    break;
                default:
                    throw new ArgumentException($"Unsupported export format: {format}.", nameof(format));
            }
            _lifetime.ThrowIfClosed();

            return DumpRawImageAsyncCore(destination, format, cancellationToken);
        }

        private Task DumpRawImageAsyncCore(Stream destination, RawImageExportFormat format, CancellationToken cancellationToken)
        {
            switch (format)
            {
                case RawImageExportFormat.RawImage:
                    return CopyRawBytesAsync(destination, _stream.Length, cancellationToken);
                case RawImageExportFormat.RawImageBootSectorOnly:
                    return CopyRawBytesAsync(destination, DefaultSectorSize, cancellationToken);
                case RawImageExportFormat.Vhd:
                    return WriteVhdAsync(destination, cancellationToken);
                case RawImageExportFormat.VhdWithPartitionTable:
                    return WriteVhdWithPartitionTableAsync(destination, cancellationToken);
                default:
                    // Unreachable: format is already caller-validated by DumpRawImageAsync.
                    throw new ArgumentException($"Unsupported export format: {format}.", nameof(format));
            }
        }

        /// <summary>
        /// Wraps the container's decrypted filesystem in a fixed-size VHD with no partition table -
        /// see <see cref="RawImageExportFormat.Vhd"/>'s own remarks for why no partition table.
        /// </summary>
        private async Task WriteVhdAsync(Stream destination, CancellationToken cancellationToken)
        {
            var capacity = _stream.Length;
            using (var disk = Disk.InitializeFixed(destination, DiscUtils.Streams.Ownership.None, capacity))
            {
                await CopyRawBytesAsync(disk.Content, capacity, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// The extra space reserved, beyond the filesystem's own size, when building a partitioned
        /// VHD - enough to comfortably cover the MBR plus BiosPartitionTable's own alignment gap
        /// before the partition's first sector (conventionally around 1 MiB), without needing to
        /// compute the exact figure ourselves.
        /// </summary>
        private const long VhdPartitionOverhead = 4 * 1024 * 1024;

        /// <summary>
        /// Wraps the container's decrypted filesystem in a fixed-size VHD with a single MBR partition
        /// around it - see <see cref="RawImageExportFormat.VhdWithPartitionTable"/>'s own remarks.
        /// </summary>
        private async Task WriteVhdWithPartitionTableAsync(Stream destination, CancellationToken cancellationToken)
        {
            var filesystemSize = _stream.Length;
            var capacity = filesystemSize + VhdPartitionOverhead;

            using (var disk = Disk.InitializeFixed(destination, DiscUtils.Streams.Ownership.None, capacity))
            {
                BiosPartitionTable.Initialize(disk, GetPartitionType(FileSystemType));
                using (var partitionStream = disk.Partitions[0].Open())
                {
                    await CopyRawBytesAsync(partitionStream, filesystemSize, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        /// <summary>
        /// The MBR partition type byte real Windows-formatted disks conventionally use for a given
        /// filesystem. MBR has no dedicated exFAT type - real exFAT partitions typically use GPT's own
        /// "Basic Data" type instead - so this maps exFAT to the same type NTFS uses (0x07), matching
        /// how MBR-partitioned exFAT volumes are conventionally marked in practice.
        /// </summary>
        private static WellKnownPartitionType GetPartitionType(FileSystemType fileSystemType)
        {
            switch (fileSystemType)
            {
                case FileSystemType.Fat:
                    return WellKnownPartitionType.WindowsFat;
                case FileSystemType.Ntfs:
                case FileSystemType.ExFat:
                    return WellKnownPartitionType.WindowsNtfs;
                default:
                    // Unreachable: fileSystemType is always a value this container was itself opened
                    // or created with, already validated at that point.
                    throw new ArgumentException($"Unsupported filesystem type: {fileSystemType}.", nameof(fileSystemType));
            }
        }

        /// <summary>
        /// Copies <paramref name="byteCount"/> bytes of the container's decrypted filesystem, from
        /// the start, to <paramref name="destination"/>.
        /// </summary>
        private async Task CopyRawBytesAsync(Stream destination, long byteCount, CancellationToken cancellationToken)
        {
            var remaining = byteCount;
            var buffer = new byte[81920];

            lock (_lifetime.Lock)
            {
                _stream.Seek(0, SeekOrigin.Begin);
            }

            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var toRead = (int)Math.Min(buffer.Length, remaining);
                int read;
                // Only the synchronous read against the shared _stream needs the lock - the same
                // object every DiscUtils filesystem call also reads/writes through (see
                // ContainerLifetime.Lock's own remarks) - not the async write to destination, which
                // touches nothing shared with the rest of this container.
                lock (_lifetime.Lock)
                {
                    read = _stream.Read(buffer, 0, toRead);
                }
                if (read == 0)
                {
                    break;
                }

                await destination.WriteAsync(buffer, 0, read, cancellationToken).ConfigureAwait(false);
                remaining -= read;
            }
        }

        /// <summary>
        /// Closes the container and releases the underlying filesystem and stream. Safe to call
        /// more than once: only the first call has any effect.
        /// </summary>
        /// <remarks>
        /// Takes <see cref="ContainerLifetime.Lock"/> - the same lock every read or write call takes
        /// only around its own DiscUtils call, not its whole async lifetime - so this can't tear the
        /// filesystem/stream down while one of those calls is actually in flight on another thread.
        /// Without this, closing a container (e.g. an app exiting, or the user clicking "close"
        /// immediately) while a write was still mid-flight could dispose the stream out from under a
        /// DiscUtils call that was partway through a multi-step on-disk update (an index or MFT
        /// change spanning more than one write), corrupting it - not merely throwing.
        /// </remarks>
        public void Close()
        {
            lock (_lifetime.Lock)
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
                // Dispose the filesystem first, so DiscUtils pushes any of its own pending writes
                // through this stream (which encrypts and writes through immediately - see
                // DecryptedBlockDeviceStream.Flush's remarks), then force those writes to physical
                // storage - not just the OS cache a plain Dispose() would leave them in - before
                // closing the file handle. See SectorDecryptor.FlushToDisk for why this matters; a
                // no-op if this container was never opened for writing.
                _fileSystem.Dispose();
                _stream.FlushToDisk();
                _stream.Dispose();
            }
        }
    }
}
