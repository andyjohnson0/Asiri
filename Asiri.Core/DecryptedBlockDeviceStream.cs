using System;
using System.IO;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Exposes a VeraCrypt container's encrypted data area as a seekable <see cref="Stream"/> of
    /// decrypted bytes, suitable for passing directly to a filesystem library such as DiscUtils.
    /// Wraps a <see cref="SectorDecryptor"/>: sectors are decrypted only as requested reads require
    /// them, and encrypted only as requested writes require them - never pre-decrypted, cached, or
    /// batched - and no encrypted bytes are ever exposed through this stream.
    /// </summary>
    /// <remarks>
    /// <see cref="CanWrite"/> reflects whether the underlying <see cref="SectorDecryptor"/> was
    /// opened for writing - fixed for this stream's whole lifetime, the same way a
    /// <see cref="FileStream"/>'s own <c>CanWrite</c> is fixed by how it was opened. It is not the
    /// same thing as a higher-level, runtime-togglable "is writing currently armed" switch: nothing
    /// at this layer knows about such a concept, by design - see <see cref="SectorDecryptor.CanWrite"/>.
    /// </remarks>
    public sealed class DecryptedBlockDeviceStream : Stream
    {
        private readonly SectorDecryptor _decryptor;
        private readonly long _length;
        private long _position;

        /// <summary>
        /// Creates a decrypted block-device stream over the given sector decryptor.
        /// </summary>
        /// <param name="decryptor">The Stage 2 sector decryptor for the container.</param>
        public DecryptedBlockDeviceStream(SectorDecryptor decryptor)
        {
            if (decryptor == null)
            {
                throw new ArgumentNullException(nameof(decryptor));
            }

            _decryptor = decryptor;
            _length = _decryptor.SectorCount * (long)_decryptor.SectorSize;
        }

        /// <inheritdoc />
        public override bool CanRead => true;

        /// <inheritdoc />
        public override bool CanSeek => true;

        /// <inheritdoc />
        public override bool CanWrite => _decryptor.CanWrite;

        /// <inheritdoc />
        public override long Length => _length;

        /// <inheritdoc />
        public override long Position
        {
            get => _position;
            set => Seek(value, SeekOrigin.Begin);
        }

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            if (offset < 0 || count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentException("Invalid buffer range.", nameof(offset));
            }

            var remaining = _length - _position;
            if (remaining <= 0 || count == 0)
            {
                return 0;
            }

            var toRead = remaining < count ? (int)remaining : count;
            var decrypted = _decryptor.ReadDecrypted(_position, toRead);
            Buffer.BlockCopy(decrypted, 0, buffer, offset, toRead);
            _position += toRead;
            return toRead;
        }

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin)
        {
            long newPosition;
            switch (origin)
            {
                case SeekOrigin.Begin:
                    newPosition = offset;
                    break;
                case SeekOrigin.Current:
                    newPosition = _position + offset;
                    break;
                case SeekOrigin.End:
                    newPosition = _length + offset;
                    break;
                default:
                    throw new ArgumentException($"Unsupported seek origin: {origin}.", nameof(origin));
            }

            if (newPosition < 0)
            {
                throw new ArgumentException("The resulting position must not be negative.", nameof(offset));
            }

            _position = newPosition;
            return _position;
        }

        /// <inheritdoc />
        public override void Flush()
        {
            // Nothing to flush: every write is encrypted and written through to the underlying file
            // immediately (see SectorDecryptor.WriteDecrypted), never buffered here.
        }

        /// <inheritdoc />
        public override void SetLength(long value)
        {
            // Unconditional, regardless of CanWrite: a VeraCrypt container's encrypted data area size
            // is fixed at creation and this library only supports fixed-size containers - there is no
            // notion of growing or shrinking one, not just a permissions restriction that opening for
            // write would lift.
            throw new NotSupportedException("This stream's length is fixed by the container's encrypted data area size and cannot be changed.");
        }

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!CanWrite)
            {
                throw new NotSupportedException("This stream was not opened for writing.");
            }
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            if (offset < 0 || count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentException("Invalid buffer range.", nameof(offset));
            }
            if (count == 0)
            {
                return;
            }
            if (count > _length - _position)
            {
                throw new IOException("Attempted to write beyond the end of the container's encrypted data area.");
            }

            var data = new byte[count];
            Buffer.BlockCopy(buffer, offset, data, 0, count);
            _decryptor.WriteDecrypted(_position, data);
            _position += count;
        }

        /// <summary>
        /// Forces every write made through this stream down to physical storage - see
        /// <see cref="SectorDecryptor.FlushToDisk"/> for why this is distinct from, and more than,
        /// this stream's own (deliberately no-op) <see cref="Flush"/>.
        /// </summary>
        internal void FlushToDisk()
        {
            _decryptor.FlushToDisk();
        }

        /// <summary>
        /// Writes already-encrypted bytes directly to an arbitrary byte offset in the underlying
        /// file, bypassing this stream's own sector-addressable data area entirely - see
        /// <see cref="SectorDecryptor.WriteRawRegion"/>.
        /// </summary>
        internal void WriteRawRegion(long offset, byte[] data)
        {
            _decryptor.WriteRawRegion(offset, data);
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            // The decryptor now holds a single file handle open for its own lifetime (rather than
            // opening one per call), so it must be disposed alongside this stream to avoid leaking it.
            if (disposing)
            {
                _decryptor.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
