using System;
using System.IO;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;
using Xunit;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for VeraCryptContainer.ChangeCredentialsAsync (issue #7). Every test opens a
    /// TemporaryContainerCopy of a real fixture first - the checked-in originals under "Test Data"
    /// are never modified. Tagged Integration, matching ReadWriteTests: every test here does at least
    /// three real PBKDF2 derivations (opening with the old credentials, then building the new primary
    /// and backup regions), on top of whatever further OpenAsync calls it makes to verify the result.
    ///
    /// This is filesystem-agnostic - a password/keyfile/PIM/hash change never touches the filesystem
    /// region at all, only the header - so, like the ContainerAccessMode gating tests in
    /// ReadWriteTests, these run once against a single NTFS fixture rather than being parameterized
    /// across every filesystem type for no added value.
    /// </summary>
    [Trait("Category", "Integration")]
    public class ChangePasswordTests
    {
        private static Task<VeraCryptContainer> OpenWritableAsync(TestContainers.ContainerFixture fixture, FileInfo path)
        {
            return VeraCryptContainer.OpenAsync(
                path, fixture.Password,
                new OpenOptions
                {
                    Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, Pim = fixture.Pim, KeyFiles = fixture.KeyFiles,
                    AccessMode = ContainerAccessMode.ReadWrite
                });
        }

        [Fact]
        public async Task ChangeCredentialsAsync_NewPasswordOnly_OldPasswordRejectedNewPasswordWorksContentIntact()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-1";

            var writable = await OpenWritableAsync(fixture, copy.File);
            try
            {
                await writable.ChangeCredentialsAsync(newPassword);
            }
            finally
            {
                writable.Close();
            }

            // The old password must no longer work.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm }));

            // The new password must work, and the volume's actual contents - proof the master key
            // was never touched - must still be exactly as before.
            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm });
            try
            {
                var file = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await file.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ChangeCredentialsAsync_CascadeCipher_WorksCorrectly()
        {
            // A 3-component cascade specifically, not just a single cipher: BuildHeaderRegionAsync's
            // key derivation and slicing (DeriveHeaderKey/SliceKeyMaterial) is shared code, but this
            // is the one test that actually exercises it with more than one component's worth of key
            // material, rather than trusting that by inference from the other tests all using AES.
            var fixture = TestContainers.SerpentTwofishAesExFat;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-8";

            var writable = await OpenWritableAsync(fixture, copy.File);
            try
            {
                await writable.ChangeCredentialsAsync(newPassword);
            }
            finally
            {
                writable.Close();
            }

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm }));

            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm });
            try
            {
                var file = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await file.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ChangeCredentialsAsync_NewHashAlgorithm_OldHashNoLongerWorksNewHashWorks()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-2";
            const HashAlgorithm newHash = HashAlgorithm.Whirlpool;

            var writable = await OpenWritableAsync(fixture, copy.File);
            try
            {
                await writable.ChangeCredentialsAsync(newPassword, new ChangeCredentialsOptions { NewHashAlgorithm = newHash });
            }
            finally
            {
                writable.Close();
            }

            // The new password with the OLD hash algorithm must not work - proves the hash actually changed.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, newPassword, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm }));

            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = newHash });
            try
            {
                var file = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await file.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ChangeCredentialsAsync_NewPim_OldPimNoLongerWorksNewPimWorks()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-3";
            const int newPim = 1; // deliberately small (16,000 iterations) to keep this test cheap.

            var writable = await OpenWritableAsync(fixture, copy.File);
            try
            {
                await writable.ChangeCredentialsAsync(newPassword, new ChangeCredentialsOptions { NewPim = newPim });
            }
            finally
            {
                writable.Close();
            }

            // The new password with the OLD (default) PIM must not work - proves the PIM actually changed.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, newPassword, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, Pim = 0 }));

            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, Pim = newPim });
            try
            {
                var file = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await file.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ChangeCredentialsAsync_NewKeyfiles_OldKeyfileNoLongerWorksNewKeyfileWorks()
        {
            var fixture = TestContainers.AesKf1ExFat;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-4";
            // A different keyfile to the fixture's own Keyfile1.bin - AesKf1Kf2ExFat's own fixture
            // list already references it, so it's reused here rather than duplicating a path.
            var newKeyFile = TestContainers.AesKf1Kf2ExFat.KeyFiles[1];

            var writable = await OpenWritableAsync(fixture, copy.File);
            try
            {
                await writable.ChangeCredentialsAsync(newPassword, new ChangeCredentialsOptions { NewKeyFiles = new[] { newKeyFile } });
            }
            finally
            {
                writable.Close();
            }

            // The new password with the OLD keyfile must not work - proves the keyfile actually changed.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, newPassword, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, KeyFiles = fixture.KeyFiles }));

            var container = await VeraCryptContainer.OpenAsync(
                copy.File, newPassword, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, KeyFiles = new[] { newKeyFile } });
            try
            {
                var file = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await file.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ChangeCredentialsAsync_WhenOpenedReadOnly_ThrowsInvalidOperationException()
        {
            // The old static method's "wrong old password" scenario no longer applies here - opening
            // itself is now the authentication step, and that already has extensive coverage
            // elsewhere (VeraCryptContainerTests, PasswordOnlyOpenAsyncTests). What's specific to
            // ChangeCredentialsAsync is that it requires ReadWrite, exactly like every other mutating
            // operation post-API-review.
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);

            var container = await VeraCryptContainer.OpenAsync(
                copy.File, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm });
            try
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() => container.ChangeCredentialsAsync("a-new-password-5"));
            }
            finally
            {
                container.Close();
            }

            // Nothing should have been written: the original password must still open the copy, with
            // its contents unaffected.
            var reopened = await VeraCryptContainer.OpenAsync(copy.File, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm });
            try
            {
                var file = await reopened.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await file.ReadAllTextAsync());
            }
            finally
            {
                reopened.Close();
            }
        }

        [Fact]
        public async Task ChangeCredentialsAsync_RewritesBothPrimaryAndBackupHeaders()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-6";

            var writable = await OpenWritableAsync(fixture, copy.File);
            try
            {
                await writable.ChangeCredentialsAsync(newPassword);
            }
            finally
            {
                writable.Close();
            }

            // Deliberately destroy the PRIMARY header region so opening can only succeed via the
            // BACKUP header - proving ChangeCredentialsAsync rewrote the backup with the new
            // credentials too, not just the primary.
            using (var stream = copy.File.Open(FileMode.Open, FileAccess.Write, FileShare.None))
            {
                var garbage = new byte[HeaderParser.HeaderRegionSize];
                stream.Write(garbage, 0, garbage.Length);
            }

            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm });
            try
            {
                var file = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await file.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task ChangeCredentialsAsync_PrimaryAndBackupRegionsHaveIndependentSalts()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);

            var writable = await OpenWritableAsync(fixture, copy.File);
            try
            {
                await writable.ChangeCredentialsAsync("a-new-password-7");
            }
            finally
            {
                writable.Close();
            }

            // Read both header regions back directly - a fresh, independent implementation of the
            // same read, rather than reaching into HeaderParser's own internals (this project's
            // convention: reflection or an independent re-implementation over InternalsVisibleTo).
            var primaryRegion = ReadBytesAt(copy.File, 0, HeaderParser.HeaderRegionSize);
            var backupOffset = copy.File.Length - HeaderParser.BackupHeaderOffsetFromEnd;
            var backupRegion = ReadBytesAt(copy.File, backupOffset, HeaderParser.HeaderRegionSize);

            // Matching VeraCrypt's own behaviour: each header location gets its own fresh salt, not
            // the same bytes written twice.
            Assert.NotEqual(primaryRegion, backupRegion);
        }

        private static byte[] ReadBytesAt(FileInfo file, long offset, int length)
        {
            using var stream = file.OpenRead();
            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[length];
            var totalRead = 0;
            while (totalRead < length)
            {
                var read = stream.Read(buffer, totalRead, length - totalRead);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }
                totalRead += read;
            }
            return buffer;
        }
    }
}
