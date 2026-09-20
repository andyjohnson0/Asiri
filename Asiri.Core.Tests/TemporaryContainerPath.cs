using System;
using System.IO;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// A fresh, guaranteed-not-to-exist path for a test that creates a brand new container from
    /// scratch (see VeraCryptContainer.CreateAsync) - the counterpart to TemporaryContainerCopy for
    /// tests that instead start from one of the checked-in real fixtures. Deletes the file, if one
    /// was actually created there, on Dispose.
    /// </summary>
    internal sealed class TemporaryContainerPath : IDisposable
    {
        public FileInfo File { get; }

        public TemporaryContainerPath()
        {
            File = new FileInfo(Path.Combine(Path.GetTempPath(), $"asiri-create-test-{Guid.NewGuid():N}.hc"));
        }

        public void Dispose()
        {
            try
            {
                File.Refresh();
                if (File.Exists)
                {
                    File.Delete();
                }
            }
            catch (IOException)
            {
                // Best-effort cleanup; a lingering handle from a test that didn't close its
                // container shouldn't fail the whole run over a leftover temp file.
            }
        }
    }
}
