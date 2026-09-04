using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils.Fat;
using uk.andyjohnson.Asiri.Abstractions;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Filesystem.Fat
{
    /// <summary>
    /// An <see cref="IDirectory"/> backed by a directory in a DiscUtils <see cref="FatFileSystem"/>.
    /// Not exposed publicly: callers only ever see the <see cref="IDirectory"/> interface.
    /// </summary>
    internal sealed class FatDirectory : IDirectory
    {
        private readonly FatFileSystem _fat;
        private readonly string _path;
        private readonly ContainerLifetime _lifetime;

        internal FatDirectory(FatFileSystem fat, string path, ContainerLifetime lifetime)
        {
            _fat = fat;
            _path = path;
            _lifetime = lifetime;
        }

        /// <inheritdoc />
        public string Name
        {
            get
            {
                _lifetime.ThrowIfClosed();
                return FatPathHelper.GetLeafName(_path);
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
                foreach (var entryPath in _fat.GetFileSystemEntries(_path))
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

                var childPath = FatPathHelper.Combine(_path, name);
                if (!_fat.DirectoryExists(childPath))
                {
                    throw new InvalidOperationException($"Directory not found: {name}");
                }
                return (IDirectory)new FatDirectory(_fat, childPath, _lifetime);
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

                var childPath = FatPathHelper.Combine(_path, name);
                if (!_fat.FileExists(childPath))
                {
                    throw new InvalidOperationException($"File not found: {name}");
                }
                return (IFile)new FatFile(_fat, childPath, _lifetime);
            }, cancellationToken);
        }

        private IFileSystemEntry CreateEntry(string entryPath)
        {
            if (_fat.DirectoryExists(entryPath))
            {
                return new FatDirectory(_fat, entryPath, _lifetime);
            }
            return new FatFile(_fat, entryPath, _lifetime);
        }
    }
}
