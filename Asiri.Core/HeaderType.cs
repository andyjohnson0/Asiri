namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Which header region a VeraCrypt container's header is read from - see
    /// <see cref="OpenOptions.HeaderPreference"/> (the caller's choice when opening) and
    /// <see cref="OpenResult.HeaderType"/> (which region an open container actually used - never
    /// <see cref="Auto"/>, since by the time a container is open, that choice has always already
    /// been resolved to one concrete region or the other).
    /// </summary>
    public enum HeaderType
    {
        /// <summary>
        /// Try the primary header first; if it fails validation, fall back to the backup header.
        /// Only a valid value for <see cref="OpenOptions.HeaderPreference"/>, and the default there -
        /// never a value <see cref="OpenResult.HeaderType"/> reports.
        /// </summary>
        Auto,

        /// <summary>
        /// The header at the start of the container file. When explicitly requested via
        /// <see cref="OpenOptions.HeaderPreference"/>, only this region is tried - no fallback to
        /// <see cref="Backup"/> if it fails validation.
        /// </summary>
        Primary,

        /// <summary>
        /// The header near the end of the container file - VeraCrypt's own recovery copy of the
        /// primary header. When explicitly requested via <see cref="OpenOptions.HeaderPreference"/>,
        /// only this region is tried - no fallback to <see cref="Primary"/> if it fails validation.
        /// </summary>
        Backup
    }
}
