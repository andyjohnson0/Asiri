namespace uk.andyjohnson.Asiri.Export
{
    /// <summary>
    /// The container format for <see cref="FileSystemExtractor.ExportAsync"/> - a real disk image
    /// built from a container's decrypted filesystem, none of it encrypted and none of it interpreted
    /// by Asiri or DiscUtils on the way out, for handing to a tool, person, real OS's own mount path,
    /// or physical medium entirely outside Asiri. Orthogonal to <see cref="PartitionTableOption"/>:
    /// whether the result additionally carries a partition table is a separate choice from which
    /// container format wraps it, so adding a new format here never doubles this enum's own size.
    /// </summary>
    public enum FileSystemExportFormat
    {
        /// <summary>
        /// The whole decrypted filesystem, written as a bare sequence of bytes with no wrapper of any
        /// kind - exactly what DiscUtils formatted and reads from, nothing added or removed. A real,
        /// usable disk image in its own right: this is what a tool like `dd`, or flashing to a USB
        /// drive, expects. Does not support <see cref="PartitionTableOption.SingleMbrPartition"/> -
        /// there is no container format here to wrap a partition table around.
        /// </summary>
        RawImage,

        /// <summary>
        /// The whole decrypted filesystem, wrapped in a fixed-size VHD. Windows can mount a VHD
        /// natively (no VeraCrypt, no Asiri involved at all), which is the point: it lets the exported
        /// filesystem be tested for real-OS validity completely independently of everything else in
        /// Asiri's own pipeline.
        /// </summary>
        Vhd,

        /// <summary>
        /// The same idea as <see cref="Vhd"/>, but wrapped in a fixed-size VHDX (the newer VHD format
        /// version) instead.
        /// </summary>
        Vhdx,

        /// <summary>
        /// The same idea as <see cref="Vhd"/>, but wrapped in a fixed-size VDI (VirtualBox's own disk
        /// format) instead.
        /// </summary>
        Vdi
    }
}
