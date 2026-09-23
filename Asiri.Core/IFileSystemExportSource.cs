using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// The minimal surface a decrypted container exposes to an external filesystem-export tool (see
    /// <c>Asiri.Export</c>'s <c>FileSystemExtractor</c>), without exposing the container's own
    /// internal stream, synchronization, or lifetime state. Exists so that exporting to a real disk
    /// container format - which needs DiscUtils' virtual-disk packages - is not a dependency every
    /// <see cref="VeraCryptContainer"/> consumer has to take, only those who actually reference
    /// <c>Asiri.Export</c>.
    /// </summary>
    public interface IFileSystemExportSource
    {
        /// <summary>The total length, in bytes, of the decrypted filesystem.</summary>
        long Length { get; }

        /// <summary>The filesystem type the decrypted data was formatted with.</summary>
        FileSystemType FileSystemType { get; }

        /// <summary>
        /// Copies <paramref name="byteCount"/> bytes of the decrypted filesystem, from the start, to
        /// <paramref name="destination"/>.
        /// </summary>
        /// <remarks>
        /// An implementation must stream this in bounded-size chunks, never materialize the whole
        /// range in memory at once - <paramref name="byteCount"/> is the size of a real container's
        /// entire decrypted filesystem, which can be arbitrarily large.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="destination"/> is null.</exception>
        /// <exception cref="ObjectDisposedException">
        /// The source container has already been closed (<see cref="VeraCryptContainer"/>'s own
        /// implementation throws this; other implementations should too).
        /// </exception>
        Task CopyBytesAsync(Stream destination, long byteCount, CancellationToken cancellationToken);
    }
}
