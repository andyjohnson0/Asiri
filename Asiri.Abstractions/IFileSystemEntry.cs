namespace uk.andyjohnson.Asiri.Abstractions
{
    /// <summary>
    /// A named entry within a VeraCrypt container's filesystem. Every entry returned by
    /// <see cref="IDirectory.GetEntries"/> is either an <see cref="IDirectory"/> or an
    /// <see cref="IFile"/>; callers distinguish the two with a type check or pattern match.
    /// </summary>
    public interface IFileSystemEntry
    {
        /// <summary>
        /// The entry's name, without any path.
        /// </summary>
        string Name { get; }
    }
}
