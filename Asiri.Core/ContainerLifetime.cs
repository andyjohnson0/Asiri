using System;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Shared state for every entry descended from one container's <see cref="VeraCryptContainer.Root"/> -
    /// a single instance is passed to every <see cref="NtfsDirectory"/>/<see cref="NtfsFile"/> (and,
    /// from a later stage, their Fat/ExFat counterparts) constructed for that container, so that:
    /// - any <see cref="IDirectory"/> or <see cref="IFile"/> obtained before
    ///   <see cref="VeraCryptContainer.Close"/> - however long the caller holds onto it - fails with a
    ///   clear, typed exception instead of failing deep inside DiscUtils' disposed internals
    ///   (<see cref="ThrowIfClosed"/>);
    /// - a mutating call fails clearly, before ever reaching DiscUtils, unless the container was
    ///   opened with <see cref="ContainerAccessMode.ReadWrite"/> (<see cref="ThrowIfNotWritable"/>);
    /// - every call into the underlying DiscUtils filesystem object - across every entry, on every
    ///   thread - is serialized through one lock (<see cref="Lock"/>), since DiscUtils' filesystem
    ///   implementations report <c>IsThreadSafe = false</c>: two calls into the same instance
    ///   concurrently, even two reads, are not guaranteed safe, and a write racing with anything else
    ///   could corrupt the filesystem's own in-memory metadata (MFT records, directory indexes,
    ///   allocation bitmaps) regardless of how well-behaved the underlying stream is on its own.
    /// </summary>
    internal sealed class ContainerLifetime
    {
        /// <param name="maxAccessMode">
        /// The access this container's underlying file handle was actually opened with - fixed for
        /// the container's whole session and never reassigned afterwards, hence a constructor
        /// parameter rather than a settable property.
        /// </param>
        public ContainerLifetime(ContainerAccessMode maxAccessMode)
        {
            MaxAccessMode = maxAccessMode;
        }

        public bool IsClosed { get; set; }

        /// <summary>
        /// The access this container's underlying file handle was actually opened with (see
        /// <see cref="VeraCryptContainer.AccessMode"/>, the public read-only view of this). This is
        /// the sole gate on whether a mutating operation is permitted - there is no separate runtime
        /// arm/disarm switch: opening or creating a container with
        /// <see cref="ContainerAccessMode.ReadWrite"/> is itself sufficient to permit writing to it.
        /// </summary>
        public ContainerAccessMode MaxAccessMode { get; }

        /// <summary>
        /// Guards every call into this container's underlying DiscUtils filesystem object, across
        /// every <see cref="IDirectory"/>/<see cref="IFile"/> descended from it and every thread. Not
        /// to be confused with <see cref="SectorDecryptor"/>'s own, separate stream-level lock, one
        /// level further down: that one only protects a single seek+read or seek+write on the raw
        /// file handle. This lock is what makes a multi-step operation like a read-modify-write
        /// (or, from DiscUtils' side, any sequence of calls one filesystem operation happens to make)
        /// atomic with respect to every other call through this container, not just each individual
        /// stream access within it.
        /// </summary>
        public object Lock { get; } = new object();

        public void ThrowIfClosed()
        {
            if (IsClosed)
            {
                throw new ObjectDisposedException(nameof(VeraCryptContainer), "The container has been closed.");
            }
        }

        public void ThrowIfNotWritable()
        {
            if (MaxAccessMode != ContainerAccessMode.ReadWrite)
            {
                throw new InvalidOperationException(
                    "The container is not open for writing. Reopen it with ContainerAccessMode.ReadWrite " +
                    "before attempting to modify it.");
            }
        }
    }
}
