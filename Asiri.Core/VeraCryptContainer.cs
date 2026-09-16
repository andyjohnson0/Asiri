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

            Stream fileStream;
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
                await HeaderParser.WriteRegionAsync(fileStream, 0, newPrimaryRegion, CancellationToken.None).ConfigureAwait(false);
                fileStream.Flush();

                var backupOffset = fileStream.Length - HeaderParser.BackupHeaderOffsetFromEnd;
                try
                {
                    await HeaderParser.WriteRegionAsync(fileStream, backupOffset, newBackupRegion, CancellationToken.None).ConfigureAwait(false);
                    fileStream.Flush();
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
                _fileSystem.Dispose();
                _stream.Dispose();
            }
        }
    }
}
