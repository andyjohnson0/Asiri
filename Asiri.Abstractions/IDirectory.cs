using System.Collections.Generic;
using System.IO;
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

        /// <summary>
        /// Lists the files directly contained in this directory whose name matches
        /// <paramref name="searchPattern"/>.
        /// </summary>
        /// <param name="searchPattern">
        /// A search pattern (e.g. "*.txt"). Defaults to "*", matching every file.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<IEnumerable<IFile>> EnumerateFilesAsync(string searchPattern = "*", CancellationToken cancellationToken = default);

        /// <summary>
        /// Lists the subdirectories directly contained in this directory whose name matches
        /// <paramref name="searchPattern"/>.
        /// </summary>
        /// <param name="searchPattern">
        /// A search pattern (e.g. "data*"). Defaults to "*", matching every subdirectory.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task<IEnumerable<IDirectory>> EnumerateDirectoriesAsync(string searchPattern = "*", CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new, empty subdirectory. Requires the container to currently be open for
        /// writing.
        /// </summary>
        /// <param name="name">The name of the new subdirectory, without any path.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>The newly created subdirectory.</returns>
        Task<IDirectory> CreateDirectoryAsync(string name, CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new, empty file. Requires the container to currently be open for writing. Throws
        /// if an entry with that name already exists - this creates a new file, it does not overwrite
        /// or truncate an existing one.
        /// </summary>
        /// <param name="name">The name of the new file, without any path.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>The newly created, empty file.</returns>
        Task<IFile> CreateFileAsync(string name, CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new file with the given content, read from <paramref name="content"/> from its
        /// current position to its end. Requires the container to currently be open for writing.
        /// Throws if an entry with that name already exists, as with the empty-file overload.
        /// </summary>
        /// <param name="name">The name of the new file, without any path.</param>
        /// <param name="content">The content to write into the new file.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>The newly created file.</returns>
        Task<IFile> CreateFileAsync(string name, Stream content, CancellationToken cancellationToken = default);

        /// <summary>
        /// Deletes this directory. Requires the container to currently be open for writing.
        /// </summary>
        /// <param name="recursive">
        /// If false - the default - deleting a non-empty directory fails, matching
        /// <see cref="System.IO.Directory.Delete(string, bool)"/>'s own convention. If true, this
        /// directory and everything in it are deleted.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        Task DeleteAsync(bool recursive = false, CancellationToken cancellationToken = default);
    }
}
