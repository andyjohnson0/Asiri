using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DiscUtils;
using DiscUtils.Partitions;
using DiscUtils.Streams;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Export
{
    /// <summary>
    /// Exports a decrypted filesystem - anything implementing <see cref="IFileSystemExportSource"/>,
    /// in practice a <c>VeraCryptContainer</c> - to a real disk image. Built against that minimal
    /// interface rather than <c>VeraCryptContainer</c> directly, so this project's DiscUtils
    /// virtual-disk dependencies stay out of Asiri.Core.
    /// </summary>
    public sealed class FileSystemExtractor
    {
        private readonly IFileSystemExportSource _source;

        public FileSystemExtractor(IFileSystemExportSource source)
        {
            _source = source ?? throw new ArgumentNullException(nameof(source));
        }

        /// <summary>
        /// Exports the source's decrypted filesystem to <paramref name="destination"/>, wrapped in
        /// <paramref name="format"/> and, optionally, a partition table.
        /// </summary>
        /// <param name="destination">
        /// The stream to write the export to. Written to starting at its current position; never
        /// sought or resized by this method.
        /// </param>
        /// <param name="format">The container format - see <see cref="FileSystemExportFormat"/>.</param>
        /// <param name="partitionTable">
        /// Whether to wrap a single MBR partition around the result - see
        /// <see cref="PartitionTableOption"/>. Must be <see cref="PartitionTableOption.None"/> for
        /// <see cref="FileSystemExportFormat.RawImage"/>.
        /// </param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        public Task ExportAsync(
            Stream destination,
            FileSystemExportFormat format = FileSystemExportFormat.RawImage,
            PartitionTableOption partitionTable = PartitionTableOption.None,
            CancellationToken cancellationToken = default)
        {
            if (destination == null)
            {
                throw new ArgumentNullException(nameof(destination));
            }
            switch (format)
            {
                case FileSystemExportFormat.RawImage:
                case FileSystemExportFormat.Vhd:
                case FileSystemExportFormat.Vhdx:
                case FileSystemExportFormat.Vdi:
                    break;
                default:
                    throw new ArgumentException($"Unsupported export format: {format}.", nameof(format));
            }
            switch (partitionTable)
            {
                case PartitionTableOption.None:
                case PartitionTableOption.SingleMbrPartition:
                    break;
                default:
                    throw new ArgumentException($"Unsupported partition table option: {partitionTable}.", nameof(partitionTable));
            }
            if (format == FileSystemExportFormat.RawImage && partitionTable != PartitionTableOption.None)
            {
                throw new ArgumentException($"{nameof(FileSystemExportFormat.RawImage)} does not support a partition table.", nameof(partitionTable));
            }

            if (format == FileSystemExportFormat.RawImage)
            {
                return _source.CopyBytesAsync(destination, _source.Length, cancellationToken);
            }

            return WriteDiskImageAsync(destination, format, partitionTable, cancellationToken);
        }

        /// <summary>
        /// The Stream-based "create a fixed-size disk of this format" factory for a given
        /// <see cref="FileSystemExportFormat"/> - the one thing that differs between formats; every
        /// other step (capacity, optional partition table, copying the filesystem in) is identical
        /// regardless of which container format wraps it, so this is the only per-format switch
        /// needed.
        /// </summary>
        private static Func<Stream, Ownership, long, VirtualDisk> GetFixedDiskInitializer(FileSystemExportFormat format)
        {
            switch (format)
            {
                case FileSystemExportFormat.Vhd:
                    return DiscUtils.Vhd.Disk.InitializeFixed;
                case FileSystemExportFormat.Vhdx:
                    return DiscUtils.Vhdx.Disk.InitializeFixed;
                case FileSystemExportFormat.Vdi:
                    return DiscUtils.Vdi.Disk.InitializeFixed;
                default:
                    // Unreachable: format is already caller-validated by ExportAsync.
                    throw new ArgumentException($"Unsupported export format: {format}.", nameof(format));
            }
        }

        /// <summary>
        /// The extra space reserved, beyond the filesystem's own size, when building a partitioned
        /// disk image - enough to comfortably cover the MBR plus BiosPartitionTable's own alignment
        /// gap before the partition's first sector (conventionally around 1 MiB), without needing to
        /// compute the exact figure ourselves.
        /// </summary>
        private const long PartitionOverhead = 4 * 1024 * 1024;

        /// <summary>
        /// VHDX manages free space in 1 MiB units - a capacity that isn't itself 1 MiB-aligned makes
        /// DiskImageFile's own free-space-table validation throw when it re-reads what InitializeFixed
        /// just wrote, confirmed empirically against a real (non-1-MiB-aligned) test container. VHD
        /// and VDI have no such constraint, so this is a no-op for them.
        /// </summary>
        private static long GetMinimumCapacityAlignment(FileSystemExportFormat format)
        {
            return format == FileSystemExportFormat.Vhdx ? 1024 * 1024 : 1;
        }

        private static long RoundUp(long value, long alignment)
        {
            var remainder = value % alignment;
            return remainder == 0 ? value : value + (alignment - remainder);
        }

        /// <summary>
        /// Builds a fixed-size disk image in <paramref name="format"/>, optionally wrapped around a
        /// single MBR partition, and copies the source's decrypted filesystem into it.
        /// </summary>
        private async Task WriteDiskImageAsync(
            Stream destination,
            FileSystemExportFormat format,
            PartitionTableOption partitionTable,
            CancellationToken cancellationToken)
        {
            var initializeFixed = GetFixedDiskInitializer(format);
            var filesystemSize = _source.Length;
            var minCapacity = partitionTable == PartitionTableOption.SingleMbrPartition
                ? filesystemSize + PartitionOverhead
                : filesystemSize;
            var capacity = RoundUp(minCapacity, GetMinimumCapacityAlignment(format));

            using (var disk = initializeFixed(destination, Ownership.None, capacity))
            {
                if (partitionTable == PartitionTableOption.SingleMbrPartition)
                {
                    BiosPartitionTable.Initialize(disk, GetPartitionType(_source.FileSystemType));
                    using (var partitionStream = disk.Partitions[0].Open())
                    {
                        await _source.CopyBytesAsync(partitionStream, filesystemSize, cancellationToken).ConfigureAwait(false);
                    }
                }
                else
                {
                    await _source.CopyBytesAsync(disk.Content, filesystemSize, cancellationToken).ConfigureAwait(false);
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
