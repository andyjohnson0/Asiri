using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core.Crypto;
using uk.andyjohnson.Asiri.Core.Crypto.Hash;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Reads and decrypts the volume header of a VeraCrypt file container.
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
        /// <see cref="TryDecryptRegionAsync"/> (see <see cref="VeraCryptContainer.OpenAsync(FileInfo, string, CancellationToken)"/>
        /// for VeraCryptContainer's own use of this) read exactly this many bytes.
        /// </summary>
        public const int HeaderRegionSize = SaltSize + EncryptedHeaderSize;

        /// <summary>
        /// The offset of the backup header region from the end of the container file.
        /// </summary>
        public const long BackupHeaderOffsetFromEnd = 131072;

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
        /// attempt. See <see cref="VeraCryptContainer.OpenAsync(FileInfo, string, CancellationToken)"/>
        /// for the motivating use: searching for the right (algorithm, hash) combination without
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

        private static Task<VeraCryptHeader> TryDecryptAndValidateAsync(byte[] region, byte[] passwordBytes, CryptoAlgorithm algorithm, HashAlgorithm hashAlgorithm, bool fromBackup, int pim, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                var salt = new byte[SaltSize];
                Buffer.BlockCopy(region, 0, salt, 0, SaltSize);

                var componentCount = CascadeDefinitions.GetComponentCount(algorithm);
                var keyMaterialSize = CascadeDefinitions.ComponentKeySize * componentCount;

                // PBKDF2 - by far the most expensive step in this whole pipeline, more so still for a
                // large PIM - so cancellation is checked immediately before it, not just once at the
                // top of the task.
                cancellationToken.ThrowIfCancellationRequested();
                var headerKey = DeriveHeaderKey(passwordBytes, salt, hashAlgorithm, componentCount, pim);

                // The derived key is laid out as all components' cipher keys concatenated, followed
                // by all components' tweak keys concatenated - see CascadeDefinitions and
                // XtsCipherSelector, which slice each component's 32-byte share out of these two
                // halves in the cascade's key-segment order.
                var headerCipherKey = new byte[keyMaterialSize];
                var headerTweakKey = new byte[keyMaterialSize];
                Buffer.BlockCopy(headerKey, 0, headerCipherKey, 0, keyMaterialSize);
                Buffer.BlockCopy(headerKey, keyMaterialSize, headerTweakKey, 0, keyMaterialSize);

                var encryptedHeader = new byte[EncryptedHeaderSize];
                Buffer.BlockCopy(region, SaltSize, encryptedHeader, 0, EncryptedHeaderSize);

                cancellationToken.ThrowIfCancellationRequested();
                var decrypted = XtsCipherSelector.Decrypt(algorithm, encryptedHeader, headerCipherKey, headerTweakKey, dataUnitNumber: 0);

                return ValidateAndBuildHeader(decrypted, algorithm, fromBackup);
            }, cancellationToken);
        }

        private static byte[] DeriveHeaderKey(byte[] passwordBytes, byte[] salt, HashAlgorithm hashAlgorithm, int componentCount, int pim)
        {
            return Pbkdf2KeyDerivation.DeriveKey(hashAlgorithm, passwordBytes, salt, GetPbkdf2IterationCount(pim), ComponentKeyLengthBits * componentCount);
        }

        private static VeraCryptHeader ValidateAndBuildHeader(byte[] d, CryptoAlgorithm algorithm, bool fromBackup)
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
                FromBackup = fromBackup
            };
        }

        private static ushort ReadUInt16BE(byte[] d, int offset)
        {
            return (ushort)((d[offset] << 8) | d[offset + 1]);
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
