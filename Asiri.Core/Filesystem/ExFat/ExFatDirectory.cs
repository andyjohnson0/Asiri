using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils.ExFat;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Filesystem.ExFat
{
    /// <summary>
    /// An <see cref="IDirectory"/> backed by a directory in a DiscUtils <see cref="ExFatFileSystem"/>.
    /// Not exposed publicly: callers only ever see the <see cref="IDirectory"/> interface.
    /// </summary>
    /// <remarks>
    /// Every call into <c>_exFat</c> below - reads and writes alike - is made under
    /// <c>_lifetime.Lock</c>, shared by every entry descended from the same container: DiscUtils'
    /// filesystem implementations report <c>IsThreadSafe = false</c>, so two calls into the same
    /// instance from different threads are not guaranteed safe even when both are reads.
    /// </remarks>
    internal sealed class ExFatDirectory : IDirectory
    {
        private readonly ExFatFileSystem _exFat;
        private string _path;
        private readonly ContainerLifetime _lifetime;

        internal ExFatDirectory(ExFatFileSystem exFat, string path, ContainerLifetime lifetime)
        {
            _exFat = exFat;
            _path = path;
            _lifetime = lifetime;
        }

        /// <summary>
        /// The underlying DiscUtils filesystem instance, exposed internally so
        /// <see cref="ExFatFile.MoveToAsync"/> (and this class's own <see cref="MoveToAsync"/>) can
        /// check a destination directory is actually from the same container - not just that it's an
        /// <see cref="ExFatDirectory"/>, which two entirely unrelated exFAT containers would both
        /// satisfy just as well.
        /// </summary>
        internal ExFatFileSystem FileSystem => _exFat;

        /// <inheritdoc />
        public string Name
        {
            get
            {
                _lifetime.ThrowIfClosed();
                return ExFatPathHelper.GetLeafName(_path);
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
                var parentPath = ExFatPathHelper.GetParentPath(_path);
                return parentPath == null ? null : new ExFatDirectory(_exFat, parentPath, _lifetime);
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
                    return _exFat.GetAttributes(_path);
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
                    return _exFat.GetCreationTimeUtc(_path);
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
                    return _exFat.GetLastWriteTimeUtc(_path);
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
                    foreach (var entryPath in _exFat.GetFileSystemEntries(_path))
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
                    foreach (var filePath in _exFat.GetFiles(_path, searchPattern))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        result.Add(new ExFatFile(_exFat, filePath, _lifetime));
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
                    foreach (var dirPath in _exFat.GetDirectories(_path, searchPattern))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        result.Add(new ExFatDirectory(_exFat, dirPath, _lifetime));
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

                var childPath = ExFatPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    if (!_exFat.DirectoryExists(childPath))
                    {
                        throw new InvalidOperationException($"Directory not found: {name}");
                    }
                    return (IDirectory)new ExFatDirectory(_exFat, childPath, _lifetime);
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

                var childPath = ExFatPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    if (!_exFat.FileExists(childPath))
                    {
                        throw new InvalidOperationException($"File not found: {name}");
                    }
                    return (IFile)new ExFatFile(_exFat, childPath, _lifetime);
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

                var childPath = ExFatPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    _exFat.CreateDirectory(childPath);
                    return (IDirectory)new ExFatDirectory(_exFat, childPath, _lifetime);
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

                var childPath = ExFatPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    // FileMode.CreateNew: this creates a new file, it does not overwrite or truncate
                    // an existing one - throws if the name is already taken (by a file or directory).
                    using (_exFat.OpenFile(childPath, FileMode.CreateNew, FileAccess.ReadWrite))
                    {
                    }
                    return (IFile)new ExFatFile(_exFat, childPath, _lifetime);
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

                var childPath = ExFatPathHelper.Combine(_path, name);
                lock (_lifetime.Lock)
                {
                    using (var fileStream = _exFat.OpenFile(childPath, FileMode.CreateNew, FileAccess.ReadWrite))
                    {
                        content.CopyTo(fileStream);
                    }
                    return (IFile)new ExFatFile(_exFat, childPath, _lifetime);
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
                    // Enforced here, ourselves, rather than trusted to DiscUtils.ExFatFileSystem's own
                    // DeleteDirectory(path, recursive) - empirically confirmed (via
                    // ReadWriteTests.DeleteAsync_NonEmptyDirectory_WithoutRecursive_Throws) that it
                    // does not actually refuse to delete a non-empty directory when recursive is
                    // false, unlike NTFS and FAT's own DeleteDirectory overloads, which do. Since the
                    // whole point of recursive defaulting to false is to prevent accidental data loss,
                    // that contract needs to hold regardless of which filesystem happens to honour it
                    // correctly on its own.
                    if (!recursive && _exFat.GetFileSystemEntries(_path).Any())
                    {
                        throw new IOException($"The directory is not empty: {_path}");
                    }
                    _exFat.DeleteDirectory(_path, recursive);
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

                var parentPath = ExFatPathHelper.GetParentPath(_path);
                if (parentPath == null)
                {
                    throw new InvalidOperationException("The root directory cannot be renamed.");
                }
                var newPath = ExFatPathHelper.Combine(parentPath, newName);

                lock (_lifetime.Lock)
                {
                    _exFat.MoveDirectory(_path, newPath);
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
            if (!(destination is ExFatDirectory exFatDestination) || !ReferenceEquals(exFatDestination.FileSystem, _exFat))
            {
                throw new ArgumentException("The destination directory must be from the same container.", nameof(destination));
            }

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();

                if (ExFatPathHelper.GetParentPath(_path) == null)
                {
                    throw new InvalidOperationException("The root directory cannot be moved.");
                }
                var newPath = ExFatPathHelper.Combine(exFatDestination._path, Name);

                lock (_lifetime.Lock)
                {
                    _exFat.MoveDirectory(_path, newPath);
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
                    _exFat.SetAttributes(_path, attributes);
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
                    _exFat.SetCreationTimeUtc(_path, creationTimeUtc);
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
                    _exFat.SetLastWriteTimeUtc(_path, lastWriteTimeUtc);
                }
            }, cancellationToken);
        }

        private IFileSystemEntry CreateEntry(string entryPath)
        {
            if (_exFat.DirectoryExists(entryPath))
            {
                return new ExFatDirectory(_exFat, entryPath, _lifetime);
            }
            return new ExFatFile(_exFat, entryPath, _lifetime);
        }
    }
}
