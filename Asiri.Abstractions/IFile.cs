using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace uk.andyjohnson.Asiri.Abstractions
{
    /// <summary>
    /// A file within a VeraCrypt container's filesystem.
    /// </summary>
    public interface IFile : IFileSystemEntry
    {
        /// <summary>
        /// Gets the file's size, in bytes.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<long> GetLengthAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Reads the entire decrypted contents of the file.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<byte[]> ReadAllBytesAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Reads the entire decrypted contents of the file, decoded as UTF-8 text.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<string> ReadAllTextAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Opens a read-only stream over the file's decrypted contents, for callers that want to
        /// read a large file incrementally rather than buffering it all at once via
        /// <see cref="ReadAllBytesAsync"/>. The returned stream becomes unusable if the container is
        /// closed while it is still open.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<Stream> OpenReadAsync(CancellationToken cancellationToken = default);
    }
}
