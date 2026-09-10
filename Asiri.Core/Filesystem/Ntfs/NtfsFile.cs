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
    internal sealed class NtfsFile : IFile
    {
        private readonly NtfsFileSystem _ntfs;
        private readonly string _path;
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
                return _ntfs.GetAttributes(_path);
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
                return _ntfs.GetCreationTimeUtc(_path);
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
                return _ntfs.GetLastWriteTimeUtc(_path);
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
                return _ntfs.GetFileLength(_path);
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

                using (var stream = _ntfs.OpenFile(_path, FileMode.Open, FileAccess.Read))
                using (var buffer = new MemoryStream())
                {
                    stream.CopyTo(buffer);
                    return buffer.ToArray();
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
                return (Stream)_ntfs.OpenFile(_path, FileMode.Open, FileAccess.Read);
            }, cancellationToken);
        }
    }
}
