using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace uk.andyjohnson.Asiri.Abstractions
{
    /// <summary>
    /// A named entry within a VeraCrypt container's filesystem. Every entry returned by
    /// <see cref="IDirectory.GetEntries"/> is either an <see cref="IDirectory"/> or an
    /// <see cref="IFile"/>; callers distinguish the two with a type check or pattern match.
    /// </summary>
    public interface IFileSystemEntry
    {
        /// <summary>
        /// The entry's name, without any path.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// The entry's full path within the container's filesystem, rooted at "\" - e.g.
        /// "\data\subtest.txt". The root directory's own path is "\".
        /// </summary>
        string Path { get; }

        /// <summary>
        /// The directory containing this entry, or null if this entry is the root directory.
        /// </summary>
        IDirectory Parent { get; }

        /// <summary>
        /// Gets the entry's filesystem attributes (read-only, hidden, system, etc).
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<FileAttributes> GetAttributesAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the UTC time the entry was created.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<DateTime> GetCreationTimeUtcAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the UTC time the entry's content was last written to.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<DateTime> GetLastWriteTimeUtcAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Renames this entry within its current parent directory. Requires the container this entry
        /// came from to currently be open for writing (opened with write access, and with writing
        /// currently armed) - implementations throw if it is not. On success, this instance's own
        /// <see cref="Name"/> and <see cref="Path"/> reflect the new name from then on - matching
        /// <see cref="System.IO.FileInfo.MoveTo(string)"/>'s own behaviour - but any other
        /// <see cref="IFileSystemEntry"/> obtained separately for the same original path is not
        /// updated and becomes stale, the same well-precedented caveat <c>FileInfo</c> itself has
        /// always had.
        /// </summary>
        /// <param name="newName">The new name, without any path.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task RenameAsync(string newName, CancellationToken cancellationToken = default);

        /// <summary>
        /// Moves this entry to a new parent directory, keeping its current name. Requires the
        /// container to be open for writing. As with <see cref="RenameAsync"/>, this instance updates
        /// itself in place on success; other instances referring to the original path become stale.
        /// </summary>
        /// <param name="destination">The directory to move this entry into.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task MoveToAsync(IDirectory destination, CancellationToken cancellationToken = default);

        /// <summary>
        /// Sets the entry's filesystem attributes (read-only, hidden, system, etc). Requires the
        /// container to be open for writing.
        /// </summary>
        /// <param name="attributes">The attributes to set.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task SetAttributesAsync(FileAttributes attributes, CancellationToken cancellationToken = default);

        /// <summary>
        /// Sets the UTC time the entry was created. Requires the container to be open for writing.
        /// </summary>
        /// <param name="creationTimeUtc">The creation time to set.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task SetCreationTimeUtcAsync(DateTime creationTimeUtc, CancellationToken cancellationToken = default);

        /// <summary>
        /// Sets the UTC time the entry's content was last written to. Requires the container to be
        /// open for writing. Note that creating or writing to a file already updates this
        /// automatically (see <see cref="IDirectory.CreateFileAsync(string, CancellationToken)"/> and
        /// <see cref="IFile.OpenWriteAsync"/>); this method is for setting it to a specific value
        /// rather than "now".
        /// </summary>
        /// <param name="lastWriteTimeUtc">The last-write time to set.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task SetLastWriteTimeUtcAsync(DateTime lastWriteTimeUtc, CancellationToken cancellationToken = default);
    }
}
