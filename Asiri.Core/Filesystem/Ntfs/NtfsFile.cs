using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils.Ntfs;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Filesystem.Ntfs
{
    /// <summary>
    /// An <see cref="IFile"/> backed by a file in a DiscUtils <see cref="NtfsFileSystem"/>. Not
    /// exposed publicly: callers only ever see the <see cref="IFile"/> interface.
    /// </summary>
    /// <remarks>
    /// Every call into <c>_ntfs</c> below - reads and writes alike - is made under
    /// <c>_lifetime.Lock</c>, shared by every entry descended from the same container: DiscUtils'
    /// filesystem implementations report <c>IsThreadSafe = false</c>, so two calls into the same
    /// instance from different threads are not guaranteed safe even when both are reads.
    /// </remarks>
    internal sealed class NtfsFile : IFile
    {
        private readonly NtfsFileSystem _ntfs;
        private string _path;
        private readonly ContainerLifetime _lifetime;

        internal NtfsFile(NtfsFileSystem ntfs, string path, ContainerLifetime lifetime)
        {
            _ntfs = ntfs;
            _path = path;
            _lifetime = lifetime;
        }

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
        public Task<long> GetLengthAsync(CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                lock (_lifetime.Lock)
                {
                    return _ntfs.GetFileLength(_path);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<byte[]> ReadAllBytesAsync(CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();

                lock (_lifetime.Lock)
                {
                    using (var stream = _ntfs.OpenFile(_path, FileMode.Open, FileAccess.Read))
                    using (var buffer = new MemoryStream())
                    {
                        stream.CopyTo(buffer);
                        return buffer.ToArray();
                    }
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<string> ReadAllTextAsync(CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();
            return ReadAllTextAsyncCore(cancellationToken);
        }

        private async Task<string> ReadAllTextAsyncCore(CancellationToken cancellationToken)
        {
            var bytes = await ReadAllBytesAsync(cancellationToken).ConfigureAwait(false);
            return Encoding.UTF8.GetString(bytes);
        }

        /// <inheritdoc />
        public Task<Stream> OpenReadAsync(CancellationToken cancellationToken = default)
        {
            _lifetime.ThrowIfClosed();

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                lock (_lifetime.Lock)
                {
                    return (Stream)_ntfs.OpenFile(_path, FileMode.Open, FileAccess.Read);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task<Stream> OpenWriteAsync(CancellationToken cancellationToken = default)
        {
            // Checked once, here, at the moment the stream is opened - not enforced for the returned
            // stream's whole lifetime. See the interface doc comment for why.
            _lifetime.ThrowIfClosed();
            _lifetime.ThrowIfNotWritable();

            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                _lifetime.ThrowIfClosed();
                _lifetime.ThrowIfNotWritable();
                lock (_lifetime.Lock)
                {
                    return (Stream)_ntfs.OpenFile(_path, FileMode.Create, FileAccess.ReadWrite);
                }
            }, cancellationToken);
        }

        /// <inheritdoc />
        public Task DeleteAsync(CancellationToken cancellationToken = default)
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
                    _ntfs.DeleteFile(_path);
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
                var newPath = NtfsPathHelper.Combine(parentPath, newName);

                lock (_lifetime.Lock)
                {
                    _ntfs.MoveFile(_path, newPath, false);
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

                var newPath = NtfsPathHelper.Combine(ntfsDestination.Path, Name);

                lock (_lifetime.Lock)
                {
                    _ntfs.MoveFile(_path, newPath, false);
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
    }
}
