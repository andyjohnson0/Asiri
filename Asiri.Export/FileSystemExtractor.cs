using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils.Partitions;
using DiscUtils.Streams;
using DiscUtils.Vhd;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Export
{
    /// <summary>
    /// Exports a decrypted filesystem - anything implementing <see cref="IFileSystemExportSource"/>,
    /// in practice a <c>VeraCryptContainer</c> - to a real disk image. Built against that minimal
    /// interface rather than <c>VeraCryptContainer</c> directly, so this project's DiscUtils
    /// virtual-disk dependency stays out of Asiri.Core.
    /// </summary>
    public sealed class FileSystemExtractor
    {
        private readonly IFileSystemExportSource _source;

        public FileSystemExtractor(IFileSystemExportSource source)
        {
            _source = source ?? throw new ArgumentNullException(nameof(source));
        }

        /// <summary>
        /// Exports the source's decrypted filesystem to <paramref name="destination"/>, in the given
        /// <paramref name="format"/>.
        /// </summary>
        /// <param name="destination">
        /// The stream to write the export to. Written to starting at its current position; never
        /// sought or resized by this method.
        /// </param>
        /// <param name="format">The export format - see <see cref="FileSystemExportFormat"/>.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        public Task ExportAsync(Stream destination, FileSystemExportFormat format = FileSystemExportFormat.RawImage, CancellationToken cancellationToken = default)
        {
            if (destination == null)
            {
                throw new ArgumentNullException(nameof(destination));
            }
            switch (format)
            {
                case FileSystemExportFormat.RawImage:
                    return _source.CopyBytesAsync(destination, _source.Length, cancellationToken);
                case FileSystemExportFormat.Vhd:
                    return WriteVhdAsync(destination, cancellationToken);
                case FileSystemExportFormat.VhdWithPartitionTable:
                    return WriteVhdWithPartitionTableAsync(destination, cancellationToken);
                default:
                    throw new ArgumentException($"Unsupported export format: {format}.", nameof(format));
            }
        }

        /// <summary>
        /// Wraps the decrypted filesystem in a fixed-size VHD with no partition table - see
        /// <see cref="FileSystemExportFormat.Vhd"/>'s own remarks for why no partition table.
        /// </summary>
        private async Task WriteVhdAsync(Stream destination, CancellationToken cancellationToken)
        {
            var capacity = _source.Length;
            using (var disk = Disk.InitializeFixed(destination, Ownership.None, capacity))
            {
                await _source.CopyBytesAsync(disk.Content, capacity, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// The extra space reserved, beyond the filesystem's own size, when building a partitioned
        /// VHD - enough to comfortably cover the MBR plus BiosPartitionTable's own alignment gap
        /// before the partition's first sector (conventionally around 1 MiB), without needing to
        /// compute the exact figure ourselves.
        /// </summary>
        private const long VhdPartitionOverhead = 4 * 1024 * 1024;

        /// <summary>
        /// Wraps the decrypted filesystem in a fixed-size VHD with a single MBR partition around it -
        /// see <see cref="FileSystemExportFormat.VhdWithPartitionTable"/>'s own remarks.
        /// </summary>
        private async Task WriteVhdWithPartitionTableAsync(Stream destination, CancellationToken cancellationToken)
        {
            var filesystemSize = _source.Length;
            var capacity = filesystemSize + VhdPartitionOverhead;

            using (var disk = Disk.InitializeFixed(destination, Ownership.None, capacity))
            {
                BiosPartitionTable.Initialize(disk, GetPartitionType(_source.FileSystemType));
                using (var partitionStream = disk.Partitions[0].Open())
                {
                    await _source.CopyBytesAsync(partitionStream, filesystemSize, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        /// <summary>
        /// The MBR partition type byte real Windows-formatted disks conventionally use for a given
        /// filesystem. MBR has no dedicated exFAT type - real exFAT partitions typically use GPT's own
        /// "Basic Data" type instead - so this maps exFAT to the same type NTFS uses (0x07), matching
        /// how MBR-partitioned exFAT volumes are conventionally marked in practice.
        /// </summary>
        private static WellKnownPartitionType GetPartitionType(FileSystemType fileSystemType)
        {
            switch (fileSystemType)
            {
                case FileSystemType.Fat:
                    return WellKnownPartitionType.WindowsFat;
                case FileSystemType.Ntfs:
                case FileSystemType.ExFat:
                    return WellKnownPartitionType.WindowsNtfs;
                default:
                    // Unreachable in practice: FileSystemType always comes from a VeraCryptContainer
                    // already validated at open/create time.
                    throw new ArgumentException($"Unsupported filesystem type: {fileSystemType}.", nameof(fileSystemType));
            }
        }
    }
}
