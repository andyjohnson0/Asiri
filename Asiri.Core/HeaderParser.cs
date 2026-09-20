using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core.Crypto;
using uk.andyjohnson.Asiri.Core.Crypto.Hash;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Reads and decrypts the volume header of a VeraCrypt file container - and, for
    /// <see cref="VeraCryptContainer.ChangeCredentialsAsync"/>, rebuilds one under a new set of
    /// credentials.
    /// </summary>
    public static class HeaderParser
    {
        private const string ExpectedMagic = "VERA";
        private const int MinHeaderVersion = 1;
        private const int MaxHeaderVersion = 5;

        private const int SaltSize = 64;
        private const int EncryptedHeaderSize = 448;

        /// <summary>
        /// The size, in bytes, of a single header region (the 64-byte salt followed by the 448-byte
        /// encrypted header), as read directly from a container file at either the primary or backup
        /// header offset. Callers building their own multi-algorithm search over
        /// <see cref="TryDecryptRegionAsync"/> (see <see cref="VeraCryptContainer.OpenAsync"/> for
        /// VeraCryptContainer's own use of this) read exactly this many bytes.
        /// </summary>
        public const int HeaderRegionSize = SaltSize + EncryptedHeaderSize;

        /// <summary>
        /// The offset of the backup header region from the end of the container file.
        /// </summary>
        public const long BackupHeaderOffsetFromEnd = 131072;

        /// <summary>
        /// The byte offset, within the container file, where a non-hidden volume's encrypted data
        /// area begins - verified against VeraCrypt's own source (Common/Volumes.h's
        /// TC_VOLUME_DATA_OFFSET), not assumed. Numerically identical to
        /// <see cref="BackupHeaderOffsetFromEnd"/> - both equal the size of one header group (a 64KB
        /// header slot plus a 64KB slot always reserved for, but unused by, a hidden volume) - kept
        /// as a separate constant since the two represent different things: this is measured from
        /// the start of the file, that one from the end.
        /// </summary>
        internal const long DataAreaOffset = 131072;

        /// <summary>
        /// The total size, in bytes, VeraCrypt reserves for headers in a non-hidden volume: a primary
        /// header group (<see cref="DataAreaOffset"/> bytes at the start of the file) plus a backup
        /// header group (<see cref="BackupHeaderOffsetFromEnd"/> bytes at the end) - verified against
        /// VeraCrypt's own source (TC_TOTAL_VOLUME_HEADERS_SIZE). See
        /// <see cref="VeraCryptContainer.CreateAsync"/>: a new container's caller-specified total file
        /// size must exceed this by however much the chosen filesystem itself needs on top.
        /// </summary>
        internal const long TotalHeaderOverheadSize = DataAreaOffset + BackupHeaderOffsetFromEnd;

        /// <summary>
        /// Computes the PBKDF2 iteration count for the given PIM (Personal Iterations Multiplier),
        /// per VeraCrypt's own formula for non-boot volumes - verified against VeraCrypt's own source
        /// (Common/Pkcs5.c, get_pkcs5_iteration_count) rather than assumed. The formula is identical
        /// across every hash algorithm this library supports for non-boot volumes (SHA-512, SHA-256,
        /// Whirlpool, BLAKE2s-256; the boot-volume formula, which does differ per hash, is irrelevant
        /// since Asiri never handles boot/system encryption), so no hash-specific branching is
        /// needed. PIM 0 - the default when unspecified - and an explicit PIM 485 both yield the same
        /// 500,000 iterations; VeraCrypt's own mount dialog displays 485 as PIM 0's "equivalent" value
        /// for exactly this reason.
        /// </summary>
        private static int GetPbkdf2IterationCount(int pim)
        {
            return pim == 0 ? 500000 : 15000 + pim * 1000;
        }

        /// <summary>
        /// The number of bits of header key material required per cascade component: a 256-bit
        /// cipher key plus a 256-bit tweak key. The total derived key length for an algorithm is
        /// this multiplied by its component count (1 for a single cipher, 2 or 3 for a cascade).
        /// </summary>
        private const int ComponentKeyLengthBits = 512;

        private const int MinSectorSize = 512;
        private const int MaxSectorSize = 4096;
        private const int CipherBlockSize = 16;

        /// <summary>
        /// Reads the volume header of a VeraCrypt container file at the given path, decrypting it
        /// with the given password. Falls back to the backup header if the primary header fails
        /// validation.
        /// </summary>
        /// <param name="path">Path to the VeraCrypt container file.</param>
        /// <param name="password">The container password.</param>
        /// <param name="algorithm">The encryption algorithm used by the container.</param>
        /// <param name="hashAlgorithm">The hash algorithm used to derive keys from the password.</param>
        /// <param name="pim">
        /// The container's PIM (Personal Iterations Multiplier), or 0 - the default - if none was
        /// set when the container was created. VeraCrypt does not store the PIM in the header, so it
        /// must be supplied by the caller, the same way the password is; it is never searched for.
        /// </param>
        /// <param name="keyFiles">
        /// Keyfiles to mix into the password, in order, or null - the default - for none. VeraCrypt
        /// does not store keyfiles in the header, so, like the password and PIM, they must be
        /// supplied by the caller and are never searched for.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>The decrypted and validated volume header.</returns>
        public static Task<VeraCryptHeader> ParseAsync(string path, string password, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, int pim = 0, IEnumerable<FileInfo> keyFiles = null, CancellationToken cancellationToken = default)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }
            return ParseAsync(new FileInfo(path), password, algorithm, hashAlgorithm, pim, keyFiles, cancellationToken);
        }

        /// <summary>
        /// Reads the volume header of a VeraCrypt container file, decrypting it with the given
        /// password. Falls back to the backup header if the primary header fails validation.
        /// </summary>
        /// <param name="path">The VeraCrypt container file.</param>
        /// <param name="password">The container password.</param>
        /// <param name="algorithm">The encryption algorithm used by the container.</param>
        /// <param name="hashAlgorithm">The hash algorithm used to derive keys from the password.</param>
        /// <param name="pim">
        /// The container's PIM (Personal Iterations Multiplier), or 0 - the default - if none was
        /// set when the container was created. VeraCrypt does not store the PIM in the header, so it
        /// must be supplied by the caller, the same way the password is; it is never searched for.
        /// </param>
        /// <param name="keyFiles">
        /// Keyfiles to mix into the password, in order, or null - the default - for none. VeraCrypt
        /// does not store keyfiles in the header, so, like the password and PIM, they must be
        /// supplied by the caller and are never searched for.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>The decrypted and validated volume header.</returns>
        public static Task<VeraCryptHeader> ParseAsync(FileInfo path, string password, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, int pim = 0, IEnumerable<FileInfo> keyFiles = null, CancellationToken cancellationToken = default)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            if (!path.Exists)
            {
                throw new ArgumentException($"Container file not found: {path.FullName}", nameof(path));
            }
            if (pim < 0)
            {
                throw new ArgumentException($"PIM must not be negative: {pim}.", nameof(pim));
            }

            return ParseAsyncCore(path, password, algorithm, hashAlgorithm, pim, keyFiles, cancellationToken);
        }

        private static async Task<VeraCryptHeader> ParseAsyncCore(FileInfo path, string password, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, int pim, IEnumerable<FileInfo> keyFiles, CancellationToken cancellationToken)
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
                var primaryRegion = await ReadRegionAsync(stream, 0, HeaderRegionSize, cancellationToken).ConfigureAwait(false);
                var header = await TryDecryptRegionAsync(primaryRegion, password, algorithm, hashAlgorithm, fromBackup: false, pim, keyFiles, cancellationToken).ConfigureAwait(false);
                if (header != null)
                {
                    return header;
                }

                if (stream.Length >= BackupHeaderOffsetFromEnd)
                {
                    var backupOffset = stream.Length - BackupHeaderOffsetFromEnd;
                    var backupRegion = await ReadRegionAsync(stream, backupOffset, HeaderRegionSize, cancellationToken).ConfigureAwait(false);
                    header = await TryDecryptRegionAsync(backupRegion, password, algorithm, hashAlgorithm, fromBackup: true, pim, keyFiles, cancellationToken).ConfigureAwait(false);
                    if (header != null)
                    {
                        return header;
                    }
                }
            }

            throw new InvalidOperationException(
                "Failed to decrypt the VeraCrypt volume header. The password may be incorrect, " +
                "or the container may not be a valid VeraCrypt volume.");
        }

        /// <summary>
        /// Attempts to decrypt and validate a single header region that has already been read from a
        /// container file, using the given password, encryption algorithm, and hash algorithm.
        /// Returns null - rather than throwing - if the region does not decrypt to a valid header
        /// with this combination, so callers can cheaply try several algorithm combinations against
        /// the same already-read bytes without repeating file I/O or paying exception overhead per
        /// attempt. See <see cref="VeraCryptContainer.OpenAsync"/> for the motivating use: searching
        /// for the right (algorithm, hash) combination without
        /// re-opening or re-reading the container file for every attempt, and without a genuine I/O
        /// failure being mistaken for "this combination didn't validate".
        /// </summary>
        /// <param name="region">
        /// The <see cref="HeaderRegionSize"/>-byte header region (salt followed by the encrypted
        /// header), as read directly from a container file at either the primary or backup header
        /// offset.
        /// </param>
        /// <param name="password">The container password.</param>
        /// <param name="algorithm">The encryption algorithm to decrypt the header with.</param>
        /// <param name="hashAlgorithm">The hash algorithm to derive keys from the password with.</param>
        /// <param name="fromBackup">Whether this region was read from the backup header location.</param>
        /// <param name="pim">
        /// The container's PIM (Personal Iterations Multiplier), or 0 - the default - if none was
        /// set when the container was created.
        /// </param>
        /// <param name="keyFiles">
        /// Keyfiles to mix into the password, in order, or null - the default - for none.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>The decrypted and validated header, or null if it did not validate.</returns>
        public static Task<VeraCryptHeader> TryDecryptRegionAsync(byte[] region, string password, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, bool fromBackup, int pim = 0, IEnumerable<FileInfo> keyFiles = null, CancellationToken cancellationToken = default)
        {
            if (region == null)
            {
                throw new ArgumentNullException(nameof(region));
            }
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            if (region.Length != HeaderRegionSize)
            {
                throw new ArgumentException($"Region must be exactly {HeaderRegionSize} bytes.", nameof(region));
            }
            if (pim < 0)
            {
                throw new ArgumentException($"PIM must not be negative: {pim}.", nameof(pim));
            }

            var passwordBytes = KeyfileMixer.Apply(Encoding.UTF8.GetBytes(password), keyFiles);
            return TryDecryptAndValidateAsync(region, passwordBytes, algorithm, hashAlgorithm, fromBackup, pim, cancellationToken);
        }

        internal static Task<byte[]> ReadRegionAsync(Stream stream, long offset, int length, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ReadRegion(stream, offset, length);
            }, cancellationToken);
        }

        private static byte[] ReadRegion(Stream stream, long offset, int length)
        {
            if (stream.Length < offset + length)
            {
                throw new InvalidOperationException("Container file is too small to contain a VeraCrypt volume header.");
            }

            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[length];
            var totalRead = 0;
            while (totalRead < length)
            {
                var read = stream.Read(buffer, totalRead, length - totalRead);
                if (read == 0)
                {
                    throw new InvalidOperationException("Container file is truncated; unable to read volume header.");
                }
                totalRead += read;
            }
            return buffer;
        }

        /// <summary>
        /// Writes a <see cref="HeaderRegionSize"/>-byte region - as built by
        /// <see cref="BuildHeaderRegionAsync"/> - to the given byte offset in an already-open,
        /// writable stream. The write-side counterpart to <see cref="ReadRegionAsync"/>.
        /// </summary>
        internal static Task WriteRegionAsync(Stream stream, long offset, byte[] region, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                WriteRegion(stream, offset, region);
            }, cancellationToken);
        }

        private static void WriteRegion(Stream stream, long offset, byte[] region)
        {
            stream.Seek(offset, SeekOrigin.Begin);
            stream.Write(region, 0, region.Length);
        }

        /// <summary>
        /// Builds a fresh <see cref="HeaderRegionSize"/>-byte header region (a random salt followed
        /// by the encrypted header) that decrypts, with the given new credentials, to the exact same
        /// plaintext header bytes as <paramref name="decryptedHeaderBytes"/>. This is the entire
        /// mechanism behind changing a container's password, keyfiles, PIM, and/or hash algorithm:
        /// the master/secondary key and every other header field live unchanged inside that
        /// plaintext, so re-encrypting it under a freshly derived key - with a fresh salt, since
        /// reusing the old one would make the old and new ciphertexts trivially related - is the
        /// whole operation. See <see cref="VeraCryptContainer.ChangeCredentialsAsync"/>.
        /// </summary>
        /// <param name="decryptedHeaderBytes">
        /// The existing header's full decrypted body (<see cref="VeraCryptHeader.DecryptedBytes"/>),
        /// obtained by successfully parsing it with the OLD credentials first - this method has no
        /// way to verify that on its own, since it never decrypts anything itself.
        /// </param>
        /// <param name="algorithm">
        /// The encryption algorithm to re-encrypt with - the same one the header was already
        /// encrypted with; this cannot change independently of the header's own plaintext content.
        /// </param>
        /// <param name="hashAlgorithm">The hash algorithm to derive the new header key with.</param>
        /// <param name="password">The new password.</param>
        /// <param name="pim">The new PIM, or 0 for the default.</param>
        /// <param name="keyFiles">The new keyfiles, in order, or null for none.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        internal static Task<byte[]> BuildHeaderRegionAsync(
            byte[] decryptedHeaderBytes, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm,
            string password, int pim, IEnumerable<FileInfo> keyFiles, CancellationToken cancellationToken)
        {
            if (decryptedHeaderBytes == null)
            {
                throw new ArgumentNullException(nameof(decryptedHeaderBytes));
            }
            if (decryptedHeaderBytes.Length != EncryptedHeaderSize)
            {
                throw new ArgumentException($"Decrypted header must be exactly {EncryptedHeaderSize} bytes.", nameof(decryptedHeaderBytes));
            }
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            if (pim < 0)
            {
                throw new ArgumentException($"PIM must not be negative: {pim}.", nameof(pim));
            }

            var passwordBytes = KeyfileMixer.Apply(Encoding.UTF8.GetBytes(password), keyFiles);
            return BuildHeaderRegionCoreAsync(decryptedHeaderBytes, algorithm, hashAlgorithm, passwordBytes, pim, cancellationToken);
        }

        private static Task<byte[]> BuildHeaderRegionCoreAsync(
            byte[] decryptedHeaderBytes, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm,
            byte[] passwordBytes, int pim, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                // A fresh salt per region (primary and backup each get their own, independent call
                // to this method - see ChangeCredentialsAsync) - System.Security.Cryptography.RandomNumberGenerator,
                // not System.Random, since this is genuinely security-sensitive: it feeds directly
                // into the key that will protect the header going forward.
                var salt = new byte[SaltSize];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                var componentCount = CascadeDefinitions.GetComponentCount(algorithm);
                var keyStream = DeriveHeaderKey(passwordBytes, salt, hashAlgorithm, componentCount, pim);
                var (headerCipherKey, headerTweakKey) = SliceKeyMaterial(keyStream, componentCount);

                var encryptedHeader = XtsCipherSelector.Encrypt(algorithm, decryptedHeaderBytes, headerCipherKey, headerTweakKey, dataUnitNumber: 0);

                var region = new byte[HeaderRegionSize];
                Buffer.BlockCopy(salt, 0, region, 0, SaltSize);
                Buffer.BlockCopy(encryptedHeader, 0, region, SaltSize, EncryptedHeaderSize);
                return region;
            }, cancellationToken);
        }

        /// <summary>
        /// Generates a fresh, random master key and secondary key for a brand new volume - the
        /// "create from scratch" counterpart to reusing an existing header's keys unchanged (see
        /// <see cref="BuildHeaderRegionAsync"/>, used instead when only the header's own encryption
        /// changes). Verified against VeraCrypt's own source (Common/Volumes.c's
        /// CreateVolumeHeaderInMemory): both keys are generated together and then sanity-checked -
        /// the master key must not be identical to the secondary key - before being accepted, since
        /// NIST SP800-38E flags identical AES-XTS key components as a weakness. A genuine CSPRNG makes
        /// this astronomically unlikely to ever fail; the loop exists only to match VeraCrypt's own
        /// defense-in-depth, not because failure is expected.
        /// </summary>
        internal static (byte[] MasterKey, byte[] SecondaryKey) GenerateMasterKeys(CryptoAlgorithm algorithm)
        {
            var keyMaterialSize = CascadeDefinitions.ComponentKeySize * CascadeDefinitions.GetComponentCount(algorithm);

            using (var rng = RandomNumberGenerator.Create())
            {
                while (true)
                {
                    var masterKey = new byte[keyMaterialSize];
                    var secondaryKey = new byte[keyMaterialSize];
                    rng.GetBytes(masterKey);
                    rng.GetBytes(secondaryKey);

                    if (!masterKey.SequenceEqual(secondaryKey))
                    {
                        return (masterKey, secondaryKey);
                    }
                }
            }
        }

        /// <summary>
        /// Builds a fresh <see cref="EncryptedHeaderSize"/>-byte plaintext volume header for a brand
        /// new, non-hidden container - the "create from scratch" counterpart to
        /// <see cref="BuildHeaderRegionAsync"/>, which only ever re-encrypts an EXISTING plaintext
        /// verbatim. Every field is laid out exactly as <see cref="ValidateAndBuildHeader"/> reads it
        /// back, verified field-for-field against VeraCrypt's own source: magic, header version, a
        /// hidden-volume size of zero, the volume/encrypted-area size set to <paramref name="dataAreaSize"/>
        /// (the DATA AREA size, not the container's total file size - see
        /// <see cref="VeraCryptContainer.CreateAsync"/> for that distinction), a master-key-scope
        /// offset of <see cref="DataAreaOffset"/>, and finally both CRC-32 checks.
        /// </summary>
        /// <param name="dataAreaSize">The size, in bytes, of the volume's encrypted data area.</param>
        /// <param name="sectorSize">The sector size, in bytes, to record in the header.</param>
        /// <param name="masterKey">The volume's master key, from <see cref="GenerateMasterKeys"/>.</param>
        /// <param name="secondaryKey">The volume's secondary key, from <see cref="GenerateMasterKeys"/>.</param>
        internal static byte[] BuildNewHeaderPlaintext(long dataAreaSize, int sectorSize, byte[] masterKey, byte[] secondaryKey)
        {
            var d = new byte[EncryptedHeaderSize];
            Encoding.ASCII.GetBytes(ExpectedMagic).CopyTo(d, 0);
            WriteUInt16BE(d, 4, (ushort)MaxHeaderVersion);
            // Not validated or interpreted by Asiri itself on read (see ValidateAndBuildHeader), but
            // it matters enormously to a REAL VeraCrypt driver: verified against VeraCrypt's own
            // source, Common/Volumes.c sets cryptoInfo->LegacyVolume = RequiredProgramVersion < 0x10b,
            // and a legacy volume is located via a completely different, much smaller data area offset
            // (TC_VOLUME_HEADER_SIZE_LEGACY, not this container's real 131072-byte one) - Driver/Ntvol.c.
            // The previous value here, 0x0108, was three short of that threshold, so every container
            // this method built was silently mounted as a legacy volume by real VeraCrypt, which then
            // decrypted from entirely the wrong offset. 0x010b matches VeraCrypt's own
            // TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION constant (Common/Volumes.h), which its own format
            // code writes for every new, non-legacy volume.
            WriteUInt16BE(d, 6, 0x010b);
            WriteInt64BE(d, 28, 0); // HiddenVolumeSize: always zero - Asiri never creates hidden volumes.
            WriteInt64BE(d, 36, dataAreaSize); // VolumeSize
            WriteInt64BE(d, 44, DataAreaOffset); // MasterKeyScopeOffset
            WriteInt64BE(d, 52, dataAreaSize); // EncryptedAreaSize
            WriteUInt32BE(d, 60, 0); // Flags
            WriteUInt32BE(d, 64, (uint)sectorSize);
            Buffer.BlockCopy(masterKey, 0, d, 192, masterKey.Length);
            Buffer.BlockCopy(secondaryKey, 0, d, 192 + masterKey.Length, secondaryKey.Length);

            WriteUInt32BE(d, 8, Crc32.Compute(d, 192, 256));
            WriteUInt32BE(d, 188, Crc32.Compute(d, 0, 188));

            return d;
        }

        private static Task<VeraCryptHeader> TryDecryptAndValidateAsync(byte[] region, byte[] passwordBytes, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, bool fromBackup, int pim, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                var salt = ExtractSalt(region);
                var componentCount = CascadeDefinitions.GetComponentCount(algorithm);

                // PBKDF2 - by far the most expensive step in this whole pipeline, more so still for a
                // large PIM - so cancellation is checked immediately before it, not just once at the
                // top of the task.
                cancellationToken.ThrowIfCancellationRequested();
                var keyStream = DeriveHeaderKey(passwordBytes, salt, hashAlgorithm, componentCount, pim);

                return DecryptAndValidate(region, keyStream, componentCount, algorithm, hashAlgorithm, fromBackup);
            }, cancellationToken);
        }

        /// <summary>
        /// Searches every <see cref="CryptoAlgorithm"/> in <paramref name="algorithmsByAscendingComponentCount"/>,
        /// for one fixed hash algorithm, against a single already-read header region - the inner
        /// loop of <see cref="VeraCryptContainer"/>'s brute-force search
        /// (<see cref="VeraCryptContainer.OpenAsync"/>).
        ///
        /// Rather than deriving a fresh PBKDF2 key per algorithm (up to 10 full derivations for this
        /// hash alone) or deriving the maximum length any algorithm might need upfront (which wastes
        /// work whenever an early, smaller-cascade algorithm turns out to be the right one - measured
        /// regression, not a hypothetical one), this uses an <see cref="IncrementalPbkdf2Stream"/>
        /// that grows only as far as the search actually needs. Trying algorithms in ascending
        /// component-count order (the caller's responsibility - see
        /// <see cref="VeraCryptContainer"/>'s <c>AlgorithmsByAscendingComponentCount</c>) means the
        /// stream almost never grows further than the winning algorithm's own component count
        /// requires, while the worst case - needing every component count before finding a match, or
        /// finding no match at all - costs no more than deriving the maximum upfront would have,
        /// since no block is ever computed twice.
        /// </summary>
        internal static Task<VeraCryptHeader> TrySearchHashAlgorithmAsync(
            byte[] region, byte[] passwordBytes, HashAlgorithm hashAlgorithm,
            IReadOnlyList<CryptoAlgorithm> algorithmsByAscendingComponentCount, bool fromBackup, int pim,
            CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                var salt = ExtractSalt(region);

                using (var prf = Pbkdf2PrfFactory.Create(hashAlgorithm, passwordBytes))
                using (var keyStream = new IncrementalPbkdf2Stream(prf, salt, GetPbkdf2IterationCount(pim)))
                {
                    foreach (var algorithm in algorithmsByAscendingComponentCount)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var componentCount = CascadeDefinitions.GetComponentCount(algorithm);
                        var keyMaterial = keyStream.GetAtLeast(2 * CascadeDefinitions.ComponentKeySize * componentCount);

                        var header = DecryptAndValidate(region, keyMaterial, componentCount, algorithm, hashAlgorithm, fromBackup);
                        if (header != null)
                        {
                            return header;
                        }
                    }

                    return null;
                }
            }, cancellationToken);
        }

        private static byte[] ExtractSalt(byte[] region)
        {
            var salt = new byte[SaltSize];
            Buffer.BlockCopy(region, 0, salt, 0, SaltSize);
            return salt;
        }

        private static VeraCryptHeader DecryptAndValidate(byte[] region, byte[] keyStream, int componentCount, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, bool fromBackup)
        {
            var (headerCipherKey, headerTweakKey) = SliceKeyMaterial(keyStream, componentCount);

            var encryptedHeader = new byte[EncryptedHeaderSize];
            Buffer.BlockCopy(region, SaltSize, encryptedHeader, 0, EncryptedHeaderSize);

            var decrypted = XtsCipherSelector.Decrypt(algorithm, encryptedHeader, headerCipherKey, headerTweakKey, dataUnitNumber: 0);

            return ValidateAndBuildHeader(decrypted, algorithm, hashAlgorithm, fromBackup);
        }

        /// <summary>
        /// Slices a component-count-specific (cipher key, tweak key) pair out of a PBKDF2 key stream.
        /// The stream is laid out as all components' cipher keys concatenated, followed by all
        /// components' tweak keys concatenated - see CascadeDefinitions and XtsCipherSelector, which
        /// slice each component's own 32-byte share out of these two halves in the cascade's
        /// key-segment order. <paramref name="keyStream"/> is expected to be exactly
        /// <c>2 * ComponentKeySize * componentCount</c> bytes - both callers
        /// (<see cref="TryDecryptAndValidateAsync"/> and <see cref="TrySearchHashAlgorithmAsync"/>)
        /// already derive or request exactly that much.
        /// </summary>
        private static (byte[] cipherKey, byte[] tweakKey) SliceKeyMaterial(byte[] keyStream, int componentCount)
        {
            var keyMaterialSize = CascadeDefinitions.ComponentKeySize * componentCount;

            var cipherKey = new byte[keyMaterialSize];
            var tweakKey = new byte[keyMaterialSize];
            Buffer.BlockCopy(keyStream, 0, cipherKey, 0, keyMaterialSize);
            Buffer.BlockCopy(keyStream, keyMaterialSize, tweakKey, 0, keyMaterialSize);
            return (cipherKey, tweakKey);
        }

        private static byte[] DeriveHeaderKey(byte[] passwordBytes, byte[] salt, HashAlgorithm hashAlgorithm, int componentCount, int pim)
        {
            return Pbkdf2KeyDerivation.DeriveKey(hashAlgorithm, passwordBytes, salt, GetPbkdf2IterationCount(pim), ComponentKeyLengthBits * componentCount);
        }

        private static VeraCryptHeader ValidateAndBuildHeader(byte[] d, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, bool fromBackup)
        {
            var magic = Encoding.ASCII.GetString(d, 0, 4);
            if (magic != ExpectedMagic)
            {
                return null;
            }

            var version = ReadUInt16BE(d, 4);
            if (version < MinHeaderVersion || version > MaxHeaderVersion)
            {
                return null;
            }

            var sectorSize = (int)ReadUInt32BE(d, 64);
            if (sectorSize < MinSectorSize || sectorSize > MaxSectorSize || sectorSize % CipherBlockSize != 0)
            {
                return null;
            }

            var keysCrc = ReadUInt32BE(d, 8);
            var headerCrc = ReadUInt32BE(d, 188);
            var actualKeysCrc = Crc32.Compute(d, 192, 256);
            var actualHeaderCrc = Crc32.Compute(d, 0, 188);
            var crcValid = actualKeysCrc == keysCrc && actualHeaderCrc == headerCrc;
            if (!crcValid)
            {
                return null;
            }

            // As with the header's own encryption key (see TryDecryptAndValidateAsync), the volume's
            // master/secondary key data is laid out as all components' cipher keys concatenated,
            // followed by all components' tweak keys concatenated.
            var keyMaterialSize = CascadeDefinitions.ComponentKeySize * CascadeDefinitions.GetComponentCount(algorithm);
            var masterKey = new byte[keyMaterialSize];
            var secondaryKey = new byte[keyMaterialSize];
            Buffer.BlockCopy(d, 192, masterKey, 0, keyMaterialSize);
            Buffer.BlockCopy(d, 192 + keyMaterialSize, secondaryKey, 0, keyMaterialSize);

            return new VeraCryptHeader
            {
                Algorithm = algorithm,
                HashAlgorithm = hashAlgorithm,
                Magic = magic,
                Version = version,
                MinRequiredVersion = ReadUInt16BE(d, 6),
                HiddenVolumeSize = ReadInt64BE(d, 28),
                VolumeSize = ReadInt64BE(d, 36),
                MasterKeyScopeOffset = ReadInt64BE(d, 44),
                EncryptedAreaSize = ReadInt64BE(d, 52),
                Flags = (int)ReadUInt32BE(d, 60),
                SectorSize = sectorSize,
                MasterKey = masterKey,
                SecondaryKey = secondaryKey,
                CrcValid = crcValid,
                FromBackup = fromBackup,
                DecryptedBytes = d
            };
        }

        private static ushort ReadUInt16BE(byte[] d, int offset)
        {
            return (ushort)((d[offset] << 8) | d[offset + 1]);
        }

        private static void WriteUInt16BE(byte[] d, int offset, ushort value)
        {
            d[offset] = (byte)(value >> 8);
            d[offset + 1] = (byte)value;
        }

        private static void WriteUInt32BE(byte[] d, int offset, uint value)
        {
            d[offset] = (byte)(value >> 24);
            d[offset + 1] = (byte)(value >> 16);
            d[offset + 2] = (byte)(value >> 8);
            d[offset + 3] = (byte)value;
        }

        private static void WriteInt64BE(byte[] d, int offset, long value)
        {
            for (var i = 0; i < 8; i++)
            {
                d[offset + i] = (byte)(value >> (56 - 8 * i));
            }
        }

        private static uint ReadUInt32BE(byte[] d, int offset)
        {
            return ((uint)d[offset] << 24) | ((uint)d[offset + 1] << 16) | ((uint)d[offset + 2] << 8) | d[offset + 3];
        }

        private static long ReadInt64BE(byte[] d, int offset)
        {
            ulong value = 0;
            for (var i = 0; i < 8; i++)
            {
                value = (value << 8) | d[offset + i];
            }
            return unchecked((long)value);
        }
    }
}
