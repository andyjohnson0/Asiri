using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils.Ntfs;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Filesystem.Ntfs
{
    /// <summary>
    /// An <see cref="IDirectory"/> backed by a directory in a DiscUtils <see cref="NtfsFileSystem"/>.
    /// Not exposed publicly: callers only ever see the <see cref="IDirectory"/> interface.
    /// </summary>
    /// <remarks>
    /// Every call into <c>_ntfs</c> below - reads and writes alike - is made under
    /// <c>_lifetime.Lock</c>, shared by every entry descended from the same container: DiscUtils'
    /// filesystem implementations report <c>IsThreadSafe = false</c>, so two calls into the same
    /// instance from different threads are not guaranteed safe even when both are reads.
    /// </remarks>
    internal sealed class NtfsDirectory : IDirectory
    {
        private readonly NtfsFileSystem _ntfs;
        private string _path;
        private readonly ContainerLifetime _lifetime;

        internal NtfsDirectory(NtfsFileSystem ntfs, string path, ContainerLifetime lifetime)
        {
            _ntfs = ntfs;
            _path = path;
            _lifetime = lifetime;
        }

        /// <summary>
        /// The underlying DiscUtils filesystem instance, exposed internally so
        /// <see cref="NtfsFile.MoveToAsync"/> (and this class's own <see cref="MoveToAsync"/>) can
        /// check a destination directory is actually from the same container - not just that it's an
        /// <see cref="NtfsDirectory"/>, which two entirely unrelated NTFS containers would both
        /// satisfy just as well.
        /// </summary>
        internal NtfsFileSystem FileSystem => _ntfs;

        /// <inheritdoc />
        public string Name
        {
            get
            {
                _lifetime.ThrowIfClosed();
                return NtfsPathHelper.GetLeafName(_path);
            }
        }

        /// <inheritdoc />
        public string Path
        {
            get
            {
                _lifetime.ThrowIfClosed();
                return _path;
            }
        }

        /// <inheritdoc />
        public IDirectory Parent
        {
            get
            {
                _lifetime.ThrowIfClosed();
                var parentPath = NtfsPathHelper.GetParentPath(_path);
                return parentPath == null ? null : new NtfsDirectory(_ntfs, parentPath, _lifetime);
            }
        }

        /// <inheritdoc />
        public Task<FileAttributes> GetAttributesAsync(CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                lock (_lifetime.Lock)
                {
                    return _ntfs.GetAttributes(_path);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<DateTime> GetCreationTimeUtcAsync(CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                lock (_lifetime.Lock)
                {
                    return _ntfs.GetCreationTimeUtc(_path);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<DateTime> GetLastWriteTimeUtcAsync(CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                lock (_lifetime.Lock)
                {
                    return _ntfs.GetLastWriteTimeUtc(_path);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<IEnumerable<IFileSystemEntry>> GetEntriesAsync(CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();

                // Materialized eagerly, not returned as a lazy LINQ query: otherwise the underlying
                // DiscUtils calls would run whenever the caller enumerates the result, which could be
                // after the container - and the ThrowIfClosed() check above - have long since passed.
                lock (_lifetime.Lock)
                {
                    var result = new List<IFileSystemEntry>();
                    foreach (var entryPath in _ntfs.GetFileSystemEntries(_path))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        result.Add(CreateEntry(entryPath));
                    }
                    return (IEnumerable<IFileSystemEntry>)result;
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<IEnumerable<IFile>> EnumerateFilesAsync(string searchPattern = "*", CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            if (searchPattern == null)
            {
                throw new ArgumentNullException(nameof(searchPattern));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();

                lock (_lifetime.Lock)
                {
                    var result = new List<IFile>();
                    foreach (var filePath in _ntfs.GetFiles(_path, searchPattern))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        result.Add(new NtfsFile(_ntfs, filePath, _lifetime));
                    }
                    return (IEnumerable<IFile>)result;
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<IEnumerable<IDirectory>> EnumerateDirectoriesAsync(string searchPattern = "*", CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            if (searchPattern == null)
            {
                throw new ArgumentNullException(nameof(searchPattern));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();

                lock (_lifetime.Lock)
                {
                    var result = new List<IDirectory>();
                    foreach (var dirPath in _ntfs.GetDirectories(_path, searchPattern))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        result.Add(new NtfsDirectory(_ntfs, dirPath, _lifetime));
                    }
                    return (IEnumerable<IDirectory>)result;
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<IDirectory> GetDirectoryAsync(string name, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();

                var childPath = NtfsPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    if (!_ntfs.DirectoryExists(childPath))
                    {
                        throw new InvalidOperationException($"Directory not found: {name}");
                    }
                    return (IDirectory)new NtfsDirectory(_ntfs, childPath, _lifetime);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<IFile> GetFileAsync(string name, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();

                var childPath = NtfsPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    if (!_ntfs.FileExists(childPath))
                    {
                        throw new InvalidOperationException($"File not found: {name}");
                    }
                    return (IFile)new NtfsFile(_ntfs, childPath, _lifetime);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<IDirectory> CreateDirectoryAsync(string name, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();

                var childPath = NtfsPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    _ntfs.CreateDirectory(childPath);
                    return (IDirectory)new NtfsDirectory(_ntfs, childPath, _lifetime);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<IFile> CreateFileAsync(string name, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();

                var childPath = NtfsPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    // FileMode.CreateNew: this creates a new file, it does not overwrite or truncate
                    // an existing one - throws if the name is already taken (by a file or directory).
                    using (_ntfs.OpenFile(childPath, FileMode.CreateNew, FileAccess.ReadWrite))
                    {
                    }
                    return (IFile)new NtfsFile(_ntfs, childPath, _lifetime);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<IFile> CreateFileAsync(string name, Stream content, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }
            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();

                var childPath = NtfsPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    using (var fileStream = _ntfs.OpenFile(childPath, FileMode.CreateNew, FileAccess.ReadWrite))
                    {
                        content.CopyTo(fileStream);
                    }
                    return (IFile)new NtfsFile(_ntfs, childPath, _lifetime);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task DeleteAsync(bool recursive = false, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();

                lock (_lifetime.Lock)
                {
                    // Enforced here, ourselves, rather than trusted entirely to
                    // DiscUtils.NtfsFileSystem's own DeleteDirectory(path, recursive) - empirically
                    // confirmed correct for NTFS, but the equivalent exFAT call was NOT (see
                    // ExFatDirectory's own version of this check), so this is enforced consistently
                    // here too rather than left dependent on each filesystem happening to honour it.
                    if (!recursive && _ntfs.GetFileSystemEntries(_path).Any())
                    {
                        throw new IOException($"The directory is not empty: {_path}");
                    }
                    _ntfs.DeleteDirectory(_path, recursive);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task RenameAsync(string newName, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();
            if (newName == null)
            {
                throw new ArgumentNullException(nameof(newName));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();

                var parentPath = NtfsPathHelper.GetParentPath(_path);
                if (parentPath == null)
                {
                    throw new InvalidOperationException("The root directory cannot be renamed.");
                }
                var newPath = NtfsPathHelper.Combine(parentPath, newName);

                lock (_lifetime.Lock)
                {
                    _ntfs.MoveDirectory(_path, newPath);
                }
                _path = newPath;
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task MoveToAsync(IDirectory destination, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();
            if (destination == null)
            {
                throw new ArgumentNullException(nameof(destination));
            }
            if (!(destination is NtfsDirectory ntfsDestination) || !ReferenceEquals(ntfsDestination.FileSystem, _ntfs))
            {
                throw new ArgumentException("The destination directory must be from the same container.", nameof(destination));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();

                if (NtfsPathHelper.GetParentPath(_path) == null)
                {
                    throw new InvalidOperationException("The root directory cannot be moved.");
                }
                var newPath = NtfsPathHelper.Combine(ntfsDestination._path, Name);

                lock (_lifetime.Lock)
                {
                    _ntfs.MoveDirectory(_path, newPath);
                }
                _path = newPath;
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task SetAttributesAsync(FileAttributes attributes, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();
                lock (_lifetime.Lock)
                {
                    _ntfs.SetAttributes(_path, attributes);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task SetCreationTimeUtcAsync(DateTime creationTimeUtc, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();
                lock (_lifetime.Lock)
                {
                    _ntfs.SetCreationTimeUtc(_path, creationTimeUtc);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task SetLastWriteTimeUtcAsync(DateTime lastWriteTimeUtc, CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();
                lock (_lifetime.Lock)
                {
                    _ntfs.SetLastWriteTimeUtc(_path, lastWriteTimeUtc);
                }
            }, cancellationToken);
        }

        private IFileSystemEntry CreateEntry(string entryPath)
        {
            if (_ntfs.DirectoryExists(entryPath))
            {
                return new NtfsDirectory(_ntfs, entryPath, _lifetime);
            }
            return new NtfsFile(_ntfs, entryPath, _lifetime);
        }
    }
}
