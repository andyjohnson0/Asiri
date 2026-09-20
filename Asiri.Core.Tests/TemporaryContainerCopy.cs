using System;
using System.IO;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Copies one of the checked-in real test containers to a temporary file for a test that needs
    /// to write to it - the checked-in originals under "Test Data" must never be modified: they are
    /// shared read-path fixtures the whole suite depends on, and the "mutate a byte, watch a test
    /// fail" validation mechanism the README describes only works if they stay exactly as real
    /// VeraCrypt produced them. The temporary copy is deleted on Dispose.
    /// </summary>
    internal sealed class TemporaryContainerCopy : IDisposable
    {
        public FileInfo File { get; }

        public TemporaryContainerCopy(FileInfo original)
        {
            var tempPath = Path.Combine(Path.GetTempPath(), $"asiri-write-test-{Guid.NewGuid():N}{original.Extension}");
            original.CopyTo(tempPath);
            File = new FileInfo(tempPath);
        }

        public void Dispose()
        {
            try
            {
                System.IO.File.Delete(File.FullName);
            }
            catch (IOException)
            {
                // Best-effort cleanup; a lingering handle from a test that didn't close its
                // container shouldn't fail the whole run over a leftover temp file.
            }
        }
    }
}
