namespace uk.andyjohnson.Asiri.Export
{
    /// <summary>
    /// Whether <see cref="FileSystemExtractor.ExportAsync"/> wraps a single partition table around
    /// the exported filesystem, orthogonal to <see cref="FileSystemExportFormat"/> (which container
    /// format, if any, wraps the result) - see that enum's own remarks. Only meaningful alongside a
    /// container format that actually supports partitioning (i.e. not
    /// <see cref="FileSystemExportFormat.RawImage"/>).
    /// </summary>
    public enum PartitionTableOption
    {
        /// <summary>
        /// No partition table - the container format's own first sector is the filesystem's boot
        /// sector directly, matching exactly how the filesystem is laid out inside the real encrypted
        /// container.
        /// </summary>
        None,

        /// <summary>
        /// A single MBR partition (of the appropriate type for the container's own filesystem type)
        /// wrapped around the filesystem, rather than placing it directly at the start of the disk.
        /// Exists alongside <see cref="None"/> specifically to separate two variables while diagnosing
        /// why a real OS doesn't recognise a container's filesystem: whether the filesystem's own
        /// content is at fault, or whether a partitioned-vs-unpartitioned disk layout is.
        /// </summary>
        SingleMbrPartition
    }
}
