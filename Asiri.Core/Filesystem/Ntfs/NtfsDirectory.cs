using System;
using System.Collections.Generic;
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
    internal sealed class NtfsDirectory : IDirectory
    {
        private readonly NtfsFileSystem _ntfs;
        private readonly string _path;
        private readonly ContainerLifetime _lifetime;

        internal NtfsDirectory(NtfsFileSystem ntfs, string path, ContainerLifetime lifetime)
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
                foreach (var entryPath in _ntfs.GetFileSystemEntries(_path))
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

                var childPath = NtfsPathHelper.Combine(_path, name);
                if (!_ntfs.DirectoryExists(childPath))
                {
                    throw new InvalidOperationException($"Directory not found: {name}");
                }
                return (IDirectory)new NtfsDirectory(_ntfs, childPath, _lifetime);
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
                if (!_ntfs.FileExists(childPath))
                {
                    throw new InvalidOperationException($"File not found: {name}");
                }
                return (IFile)new NtfsFile(_ntfs, childPath, _lifetime);
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
