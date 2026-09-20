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

        /// <summary>
        /// Opens a writable stream over the file's contents (truncating any existing content, the
        /// same as <see cref="System.IO.FileMode.Create"/>), for writing a large file incrementally
        /// rather than supplying it all at once. Requires the container to currently be open for
        /// writing at the moment this is called - but that requirement is checked only once, here:
        /// if writing is disarmed later while this stream is still open and in use, the stream itself
        /// does not retroactively stop working. The returned stream becomes unusable if the container
        /// is closed while it is still open, the same as <see cref="OpenReadAsync"/>.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<Stream> OpenWriteAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Deletes this file. Requires the container to currently be open for writing.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task DeleteAsync(CancellationToken cancellationToken = default);
    }
}
