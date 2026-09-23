using System.IO;

namespace uk.andyjohnson.Asiri.Export.Tests
{
    /// <summary>
    /// Simulates a destination running out of physical disk space partway through a write, without
    /// needing an actual full disk: SetLength (used by DiscUtils to pre-extend a fixed VHD, which on
    /// a real NTFS volume typically succeeds without reserving physical blocks up front) always
    /// succeeds, but Write throws once the caller has written more than <paramref name="writeLimit"/>
    /// bytes in total - mimicking the point where a real disk's free space would actually run out.
    /// </summary>
    internal sealed class DiskFullSimulatingStream : MemoryStream
    {
        private readonly long _writeLimit;
        private long _bytesWritten;

        public DiskFullSimulatingStream(long writeLimit)
        {
            _writeLimit = writeLimit;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _bytesWritten += count;
            if (_bytesWritten > _writeLimit)
            {
                throw new IOException("Simulated disk full: there is not enough space on the disk.");
            }
            base.Write(buffer, offset, count);
        }
    }
}
