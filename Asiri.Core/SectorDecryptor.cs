using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core.Crypto;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Decrypts individual sectors of a VeraCrypt container's encrypted data area on demand, using
    /// the master keys extracted from the volume header by <see cref="HeaderParser"/>. Sectors are
    /// read and decrypted only when requested; the container is never pre-decrypted or cached. Holds
    /// a single <see cref="FileStream"/> open for the lifetime of the instance, rather than opening
    /// and closing one per call.
    /// </summary>
    public sealed class SectorDecryptor : IDisposable
    {
        /// <summary>
        /// The AES-XTS data unit size used by VeraCrypt, fixed at 512 bytes regardless of the
        /// volume's sector size. A sector larger than 512 bytes is decrypted as several
        /// independently-tweaked 512-byte data units, each with its own sequence number.
        /// </summary>
        private const int DataUnitSize = 512;

        private readonly VeraCryptHeader _header;
        private readonly FileStream _stream;

        // Guards _stream.Seek()+Read(), since the stream is now shared for the decryptor's whole
        // lifetime rather than opened fresh per call: concurrent async callers (e.g. two files being
        // read at once through the same container) would otherwise race on the stream's position.
        private readonly object _streamLock = new object();

        private bool _disposed;

        private SectorDecryptor(VeraCryptHeader header, FileStream stream)
        {
            _header = header;
            _stream = stream;
        }

        /// <summary>
        /// Creates a decryptor for the given container file, using the master keys and layout
        /// information from an already-parsed volume header. Opens and holds a single file handle
        /// for the lifetime of the returned decryptor.
        /// </summary>
        /// <param name="containerFile">The VeraCrypt container file.</param>
        /// <param name="header">The container's decrypted and validated volume header.</param>
        /// <param name="cancellationToken">
        /// A token to cancel the operation. Cancellation cannot interrupt the file-open call itself
        /// once started, only take effect before it.
        /// </param>
        public static Task<SectorDecryptor> CreateAsync(FileInfo containerFile, VeraCryptHeader header, CancellationToken cancellationToken = default)
        {
            if (containerFile == null)
            {
                throw new ArgumentNullException(nameof(containerFile));
            }
            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }
            if (!containerFile.Exists)
            {
                throw new ArgumentException($"Container file not found: {containerFile.FullName}", nameof(containerFile));
            }
            if (header.SectorSize <= 0 || header.SectorSize % DataUnitSize != 0)
            {
                throw new ArgumentException($"Unsupported sector size: {header.SectorSize}.", nameof(header));
            }

            return CreateAsyncCore(containerFile, header, cancellationToken);
        }

        /// <summary>
        /// Creates a decryptor for the given container file path, using the master keys and layout
        /// information from an already-parsed volume header. Opens and holds a single file handle
        /// for the lifetime of the returned decryptor.
        /// </summary>
        /// <param name="containerPath">Path to the VeraCrypt container file.</param>
        /// <param name="header">The container's decrypted and validated volume header.</param>
        /// <param name="cancellationToken">
        /// A token to cancel the operation. Cancellation cannot interrupt the file-open call itself
        /// once started, only take effect before it.
        /// </param>
        public static Task<SectorDecryptor> CreateAsync(string containerPath, VeraCryptHeader header, CancellationToken cancellationToken = default)
        {
            if (containerPath == null)
            {
                throw new ArgumentNullException(nameof(containerPath));
            }
            return CreateAsync(new FileInfo(containerPath), header, cancellationToken);
        }

        private static Task<SectorDecryptor> CreateAsyncCore(FileInfo containerFile, VeraCryptHeader header, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                FileStream stream;
                try
                {
                    stream = new FileStream(
                        containerFile.FullName,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read,
                        bufferSize: header.SectorSize,
                        FileOptions.RandomAccess);
                }
                catch (Exception ex) when (!(ex is ArgumentException || ex is ArgumentNullException || ex is OperationCanceledException))
                {
                    throw new InvalidOperationException($"Unable to open container file: {containerFile.FullName}", ex);
                }

                return new SectorDecryptor(header, stream);
            }, cancellationToken);
        }

        /// <summary>
        /// The sector size, in bytes, of the underlying volume.
        /// </summary>
        public int SectorSize => _header.SectorSize;

        /// <summary>
        /// The number of whole sectors in the volume's encrypted data area.
        /// </summary>
        public long SectorCount => _header.EncryptedAreaSize / _header.SectorSize;

        /// <summary>
        /// Decrypts a single sector of the volume's encrypted data area.
        /// </summary>
        /// <param name="sectorIndex">
        /// The zero-based logical sector index within the encrypted data area. Sector 0 is the
        /// first sector of the volume as seen by its filesystem.
        /// </param>
        /// <param name="cancellationToken">
        /// A token to cancel the operation. Checked before decryption begins; cancellation cannot
        /// interrupt the read or the AES-XTS decrypt of a single sector once started.
        /// </param>
        /// <returns>The decrypted bytes of the sector, <see cref="SectorSize"/> bytes long.</returns>
        public Task<byte[]> DecryptSectorAsync(long sectorIndex, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (sectorIndex < 0 || sectorIndex >= SectorCount)
            {
                throw new ArgumentException($"Sector index {sectorIndex} is out of range.", nameof(sectorIndex));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                ThrowIfDisposed();
                return DecryptSector(sectorIndex);
            }, cancellationToken);
        }

        /// <summary>
        /// Decrypts a byte range of the volume's encrypted data area. The range may fall within a
        /// single sector or span multiple consecutive sectors; only the sectors that overlap the
        /// requested range are read and decrypted.
        /// </summary>
        /// <param name="offset">The zero-based byte offset within the encrypted data area.</param>
        /// <param name="count">The number of bytes to decrypt.</param>
        /// <param name="cancellationToken">
        /// A token to cancel the operation, checked between sectors when the range spans more than
        /// one - cancellation cannot interrupt the read or decrypt of a sector already in progress.
        /// </param>
        /// <returns>The decrypted bytes, exactly <paramref name="count"/> bytes long.</returns>
        public Task<byte[]> ReadDecryptedAsync(long offset, int count, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (offset < 0)
            {
                throw new ArgumentException("Offset must not be negative.", nameof(offset));
            }
            if (count < 0)
            {
                throw new ArgumentException("Count must not be negative.", nameof(count));
            }
            if (count > 0 && offset + count > _header.EncryptedAreaSize)
            {
                throw new ArgumentException("The requested range extends beyond the encrypted data area.", nameof(count));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                ThrowIfDisposed();
                return ReadDecryptedCore(offset, count, cancellationToken);
            }, cancellationToken);
        }

        /// <summary>
        /// Synchronous single-sector decrypt, used internally by <see cref="DecryptedBlockDeviceStream"/>,
        /// which must remain a plain synchronous <see cref="Stream"/> since DiscUtils calls it
        /// synchronously and has no awareness of async or cancellation.
        /// </summary>
        internal byte[] DecryptSector(long sectorIndex)
        {
            if (sectorIndex < 0 || sectorIndex >= SectorCount)
            {
                throw new ArgumentException($"Sector index {sectorIndex} is out of range.", nameof(sectorIndex));
            }
            ThrowIfDisposed();

            var fileOffset = _header.MasterKeyScopeOffset + sectorIndex * _header.SectorSize;
            var cipherText = new byte[_header.SectorSize];

            lock (_streamLock)
            {
                _stream.Seek(fileOffset, SeekOrigin.Begin);
                var totalRead = 0;
                while (totalRead < cipherText.Length)
                {
                    var read = _stream.Read(cipherText, totalRead, cipherText.Length - totalRead);
                    if (read == 0)
                    {
                        throw new InvalidOperationException("Container file is truncated; unable to read sector.");
                    }
                    totalRead += read;
                }
            }

            var plainText = new byte[cipherText.Length];
            var dataUnitCount = cipherText.Length / DataUnitSize;
            var dataUnitBuffer = new byte[DataUnitSize];
            for (var i = 0; i < dataUnitCount; i++)
            {
                var chunkOffset = i * DataUnitSize;
                Buffer.BlockCopy(cipherText, chunkOffset, dataUnitBuffer, 0, DataUnitSize);

                var dataUnitNumber = (fileOffset + chunkOffset) / DataUnitSize;
                var decryptedChunk = XtsCipherSelector.Decrypt(_header.Algorithm, dataUnitBuffer, _header.MasterKey, _header.SecondaryKey, dataUnitNumber);

                Buffer.BlockCopy(decryptedChunk, 0, plainText, chunkOffset, DataUnitSize);
            }

            return plainText;
        }

        /// <summary>
        /// Synchronous multi-sector read, used internally by <see cref="DecryptedBlockDeviceStream"/>
        /// for the same reason as <see cref="DecryptSector"/>.
        /// </summary>
        internal byte[] ReadDecrypted(long offset, int count)
        {
            return ReadDecryptedCore(offset, count, cancellationToken: null);
        }

        private byte[] ReadDecryptedCore(long offset, int count, CancellationToken? cancellationToken)
        {
            var result = new byte[count];
            if (count == 0)
            {
                return result;
            }

            var firstSector = offset / _header.SectorSize;
            var lastSector = (offset + count - 1) / _header.SectorSize;

            var resultPos = 0;
            for (var sectorIndex = firstSector; sectorIndex <= lastSector; sectorIndex++)
            {
                cancellationToken?.ThrowIfCancellationRequested();

                var sector = DecryptSector(sectorIndex);

                var sectorStart = sectorIndex * _header.SectorSize;
                var copyStart = Math.Max(offset, sectorStart);
                var copyEnd = Math.Min(offset + count, sectorStart + _header.SectorSize);
                var copyLength = (int)(copyEnd - copyStart);

                Buffer.BlockCopy(sector, (int)(copyStart - sectorStart), result, resultPos, copyLength);
                resultPos += copyLength;
            }

            return result;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(SectorDecryptor));
            }
        }

        /// <summary>
        /// Closes the underlying file handle. Safe to call more than once: only the first call has
        /// any effect.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            _stream.Dispose();
        }
    }
}
