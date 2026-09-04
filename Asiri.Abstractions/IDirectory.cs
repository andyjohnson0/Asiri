using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace uk.andyjohnson.Asiri.Abstractions
{
    /// <summary>
    /// A directory within a VeraCrypt container's filesystem.
    /// </summary>
    public interface IDirectory : IFileSystemEntry
    {
        /// <summary>
        /// Lists the files and subdirectories directly contained in this directory.
        /// </summary>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<IEnumerable<IFileSystemEntry>> GetEntriesAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the subdirectory with the given name.
        /// </summary>
        /// <param name="name">The name of the subdirectory, without any path.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<IDirectory> GetDirectoryAsync(string name, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the file with the given name.
        /// </summary>
        /// <param name="name">The name of the file, without any path.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<IFile> GetFileAsync(string name, CancellationToken cancellationToken = default);
    }
}
