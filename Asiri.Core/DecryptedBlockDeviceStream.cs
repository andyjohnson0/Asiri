using System;
using System.IO;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Exposes a VeraCrypt container's encrypted data area as a read-only, seekable
    /// <see cref="Stream"/> of decrypted bytes, suitable for passing directly to a filesystem
    /// library such as DiscUtils. Wraps a Stage 2 <see cref="SectorDecryptor"/>: sectors are
    /// decrypted only as requested reads require them, never pre-decrypted or cached, and no
    /// encrypted bytes are ever exposed through this stream.
    /// </summary>
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
        public override bool CanWrite => false;

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
            // Nothing to flush: this stream is read-only and holds no buffered write state.
        }

        /// <inheritdoc />
        public override void SetLength(long value)
        {
            throw new NotSupportedException("This stream is read-only.");
        }

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("This stream is read-only.");
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
