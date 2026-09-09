using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils.ExFat;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Filesystem.ExFat
{
    /// <summary>
    /// An <see cref="IFile"/> backed by a file in a DiscUtils <see cref="ExFatFileSystem"/>. Not
    /// exposed publicly: callers only ever see the <see cref="IFile"/> interface.
    /// </summary>
    internal sealed class ExFatFile : IFile
    {
        private readonly ExFatFileSystem _exFat;
        private readonly string _path;
        private readonly ContainerLifetime _lifetime;

        internal ExFatFile(ExFatFileSystem exFat, string path, ContainerLifetime lifetime)
        {
            _exFat = exFat;
            _path = path;
            _lifetime = lifetime;
        }

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
                return _exFat.GetAttributes(_path);
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
                return _exFat.GetCreationTimeUtc(_path);
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
                return _exFat.GetLastWriteTimeUtc(_path);
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
                return _exFat.GetFileLength(_path);
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

                using (var stream = _exFat.OpenFile(_path, FileMode.Open, FileAccess.Read))
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
                return (Stream)_exFat.OpenFile(_path, FileMode.Open, FileAccess.Read);
            }, cancellationToken);
        }
    }
}
