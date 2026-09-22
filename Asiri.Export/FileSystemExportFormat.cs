namespace uk.andyjohnson.Asiri.Export
{
    /// <summary>
    /// The output format for <see cref="FileSystemExtractor.ExportAsync"/> - a real disk image built
    /// from a container's decrypted filesystem, none of it encrypted and none of it interpreted by
    /// Asiri or DiscUtils on the way out, for handing to a tool, person, real OS's own mount path, or
    /// physical medium entirely outside Asiri.
    /// </summary>
    public enum FileSystemExportFormat
    {
        /// <summary>
        /// The whole decrypted filesystem, written as a bare sequence of bytes with no wrapper of any
        /// kind - exactly what DiscUtils formatted and reads from, nothing added or removed. A real,
        /// usable disk image in its own right: this is what a tool like `dd`, or flashing to a USB
        /// drive, expects.
        /// </summary>
        RawImage,

        /// <summary>
        /// The whole decrypted filesystem, wrapped in a fixed-size VHD with no partition table - a
        /// single, unpartitioned "superfloppy"-style virtual disk whose own first sector is the
        /// filesystem's boot sector, matching exactly how the filesystem is laid out inside the real
        /// encrypted container. Windows can mount a VHD natively (no VeraCrypt, no Asiri involved at
        /// all), which is the point: it lets the exported filesystem be tested for real-OS validity
        /// completely independently of everything else in Asiri's own pipeline.
        /// </summary>
        Vhd,

        /// <summary>
        /// The same idea as <see cref="Vhd"/>, but with a single MBR partition (of the appropriate
        /// type for the container's own filesystem type) wrapped around the filesystem, rather than
        /// placing it directly at the start of the disk. Exists alongside <see cref="Vhd"/>
        /// specifically to separate two variables while diagnosing why a real OS doesn't recognise a
        /// container's filesystem: whether the filesystem's own content is at fault, or whether a
        /// partitioned-vs-unpartitioned disk layout is.
        /// </summary>
        VhdWithPartitionTable
    }
}
