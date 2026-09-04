using System;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Tracks whether the <see cref="VeraCryptContainer"/> that created a tree of
    /// <see cref="NtfsDirectory"/>/<see cref="NtfsFile"/> objects has been closed. A single instance
    /// is shared by every entry descended from a container's <see cref="VeraCryptContainer.Root"/>,
    /// so that any <see cref="IDirectory"/> or <see cref="IFile"/> obtained before
    /// <see cref="VeraCryptContainer.Close"/> - however long the caller holds onto it - fails with a
    /// clear, typed exception instead of failing deep inside DiscUtils' disposed internals.
    /// </summary>
    internal sealed class ContainerLifetime
    {
        public bool IsClosed { get; set; }

        public void ThrowIfClosed()
        {
            if (IsClosed)
            {
                throw new ObjectDisposedException(nameof(VeraCryptContainer), "The container has been closed.");
            }
        }
    }
}
