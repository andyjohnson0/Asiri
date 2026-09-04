using System;
using System.Collections.Generic;
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
    internal sealed class ExFatDirectory : IDirectory
    {
        private readonly ExFatFileSystem _exFat;
        private readonly string _path;
        private readonly ContainerLifetime _lifetime;

        internal ExFatDirectory(ExFatFileSystem exFat, string path, ContainerLifetime lifetime)
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
                var result = new List<IFileSystemEntry>();
                foreach (var entryPath in _exFat.GetFileSystemEntries(_path))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    result.Add(CreateEntry(entryPath));
                }
                return (IEnumerable<IFileSystemEntry>)result;
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
                if (!_exFat.DirectoryExists(childPath))
                {
                    throw new InvalidOperationException($"Directory not found: {name}");
                }
                return (IDirectory)new ExFatDirectory(_exFat, childPath, _lifetime);
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
                if (!_exFat.FileExists(childPath))
                {
                    throw new InvalidOperationException($"File not found: {name}");
                }
                return (IFile)new ExFatFile(_exFat, childPath, _lifetime);
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
