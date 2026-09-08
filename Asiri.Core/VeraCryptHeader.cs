using System;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Represents the decrypted and validated fields of a VeraCrypt volume header.
    /// </summary>
    public sealed class VeraCryptHeader
    {
        /// <summary>
        /// The encryption algorithm this header was successfully decrypted with. Carried on the
        /// header - rather than passed alongside it as a separate parameter - so a header and the
        /// algorithm used to decrypt it can never be mismatched by a caller.
        /// </summary>
        public CryptoAlgorithm Algorithm { get; internal set; }

        /// <summary>
        /// The hash algorithm used to derive keys from the password for this header, via PBKDF2.
        /// Carried on the header for the same reason as <see cref="Algorithm"/>.
        /// </summary>
        public HashAlgorithm HashAlgorithm { get; internal set; }

        /// <summary>
        /// The 4-character magic string identifying a VeraCrypt volume header. Expected value is "VERA".
        /// </summary>
        public string Magic { get; internal set; } = string.Empty;

        /// <summary>
        /// The header format version.
        /// </summary>
        public int Version { get; internal set; }

        /// <summary>
        /// The minimum program version required to open the volume.
        /// </summary>
        public int MinRequiredVersion { get; internal set; }

        /// <summary>
        /// The size, in bytes, of a hidden volume. Zero for a normal (non-hidden) volume.
        /// </summary>
        public long HiddenVolumeSize { get; internal set; }

        /// <summary>
        /// The total size, in bytes, of the volume.
        /// </summary>
        public long VolumeSize { get; internal set; }

        /// <summary>
        /// The byte offset of the start of the master key scope (the encrypted data area).
        /// </summary>
        public long MasterKeyScopeOffset { get; internal set; }

        /// <summary>
        /// The size, in bytes, of the encrypted area within the master key scope.
        /// </summary>
        public long EncryptedAreaSize { get; internal set; }

        /// <summary>
        /// Header flag bits.
        /// </summary>
        public int Flags { get; internal set; }

        /// <summary>
        /// The sector size, in bytes, used by the volume.
        /// </summary>
        public int SectorSize { get; internal set; }

        /// <summary>
        /// The primary master key used for XTS data encryption. For a cascade, this is every
        /// component cipher's 256-bit data key concatenated together, in the cascade's key-segment
        /// order (see <see cref="Crypto.CascadeDefinitions"/>) - 32 bytes for a single cipher, up to
        /// 96 bytes for a three-cipher cascade.
        /// </summary>
        public byte[] MasterKey { get; internal set; } = Array.Empty<byte>();

        /// <summary>
        /// The secondary master key used for XTS tweak encryption. Laid out the same way as
        /// <see cref="MasterKey"/>, one 256-bit tweak key per component cipher.
        /// </summary>
        public byte[] SecondaryKey { get; internal set; } = Array.Empty<byte>();

        /// <summary>
        /// True if both header CRC-32 checks (header fields and master keys) passed validation.
        /// </summary>
        public bool CrcValid { get; internal set; }

        /// <summary>
        /// True if this header was recovered from the backup header at the end of the container
        /// rather than the primary header at the start.
        /// </summary>
        public bool FromBackup { get; internal set; }
    }
}
