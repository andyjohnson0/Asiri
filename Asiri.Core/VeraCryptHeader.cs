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
        /// The primary master key used for AES-XTS data encryption.
        /// </summary>
        public byte[] MasterKey { get; internal set; } = Array.Empty<byte>();

        /// <summary>
        /// The secondary master key used for AES-XTS tweak encryption.
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
