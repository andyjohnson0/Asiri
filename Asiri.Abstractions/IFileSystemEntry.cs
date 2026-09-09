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
    }
}
