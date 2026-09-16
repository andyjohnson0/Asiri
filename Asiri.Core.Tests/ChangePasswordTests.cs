using System;
using System.IO;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;
using Xunit;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for VeraCryptContainer.ChangePasswordAsync (issue #7). Every test opens a
    /// TemporaryContainerCopy of a real fixture first - the checked-in originals under "Test Data"
    /// are never modified. Tagged Integration, matching ReadWriteTests: every test here does at least
    /// three real PBKDF2 derivations (reading the old header, then building the new primary and
    /// backup regions), on top of whatever OpenAsync calls it makes to verify the result.
    ///
    /// This is filesystem-agnostic - a password/keyfile/PIM/hash change never touches the filesystem
    /// region at all, only the header - so, like the ContainerAccessMode/IsWritable gating tests in
    /// ReadWriteTests, these run once against a single NTFS fixture rather than being parameterized
    /// across every filesystem type for no added value.
    /// </summary>
    [Trait("Category", "Integration")]
    public class ChangePasswordTests
    {
        [Fact]
        public async Task ChangePasswordAsync_NewPasswordOnly_OldPasswordRejectedNewPasswordWorksContentIntact()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-1";

            await VeraCryptContainer.ChangePasswordAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.Pim, fixture.KeyFiles,
                newPassword, newPim: 0, newKeyFiles: null);

            // The old password must no longer work.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType));

            // The new password must work, and the volume's actual contents - proof the master key
            // was never touched - must still be exactly as before.
            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType);
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
        public async Task ChangePasswordAsync_CascadeCipher_WorksCorrectly()
        {
            // A 3-component cascade specifically, not just a single cipher: BuildHeaderRegionAsync's
            // key derivation and slicing (DeriveHeaderKey/SliceKeyMaterial) is shared code, but this
            // is the one test that actually exercises it with more than one component's worth of key
            // material, rather than trusting that by inference from the other tests all using AES.
            var fixture = TestContainers.SerpentTwofishAesExFat;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-8";

            await VeraCryptContainer.ChangePasswordAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.Pim, fixture.KeyFiles,
                newPassword, newPim: 0, newKeyFiles: null);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType));

            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType);
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
        public async Task ChangePasswordAsync_NewHashAlgorithm_OldHashNoLongerWorksNewHashWorks()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-2";
            const HashAlgorithm newHash = HashAlgorithm.Whirlpool;

            await VeraCryptContainer.ChangePasswordAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.Pim, fixture.KeyFiles,
                newPassword, newPim: 0, newKeyFiles: null, newHashAlgorithm: newHash);

            // The new password with the OLD hash algorithm must not work - proves the hash actually changed.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, newPassword, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType));

            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, fixture.Algorithm, newHash, fixture.FilesystemType);
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
        public async Task ChangePasswordAsync_NewPim_OldPimNoLongerWorksNewPimWorks()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-3";
            const int newPim = 1; // deliberately small (16,000 iterations) to keep this test cheap.

            await VeraCryptContainer.ChangePasswordAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.Pim, fixture.KeyFiles,
                newPassword, newPim, newKeyFiles: null);

            // The new password with the OLD (default) PIM must not work - proves the PIM actually changed.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, newPassword, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType, pim: 0));

            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType, pim: newPim);
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
        public async Task ChangePasswordAsync_NewKeyfiles_OldKeyfileNoLongerWorksNewKeyfileWorks()
        {
            var fixture = TestContainers.AesKf1ExFat;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-4";
            // A different keyfile to the fixture's own Keyfile1.bin - AesKf1Kf2ExFat's own fixture
            // list already references it, so it's reused here rather than duplicating a path.
            var newKeyFile = TestContainers.AesKf1Kf2ExFat.KeyFiles[1];

            await VeraCryptContainer.ChangePasswordAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.Pim, fixture.KeyFiles,
                newPassword, newPim: 0, newKeyFiles: new[] { newKeyFile });

            // The new password with the OLD keyfile must not work - proves the keyfile actually changed.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(copy.File, newPassword, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType, keyFiles: fixture.KeyFiles));

            var container = await VeraCryptContainer.OpenAsync(
                copy.File, newPassword, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType, keyFiles: new[] { newKeyFile });
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
        public async Task ChangePasswordAsync_WrongOldPassword_ThrowsAndLeavesContainerUnchanged()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.ChangePasswordAsync(
                    copy.File, "definitely-the-wrong-password", fixture.Algorithm, fixture.HashAlgorithm, fixture.Pim, fixture.KeyFiles,
                    "a-new-password-5", newPim: 0, newKeyFiles: null));

            // Nothing should have been written: the TRUE original password must still open the copy,
            // with its contents unaffected.
            var container = await VeraCryptContainer.OpenAsync(copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType);
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
        public async Task ChangePasswordAsync_RewritesBothPrimaryAndBackupHeaders()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);
            const string newPassword = "a-new-password-6";

            await VeraCryptContainer.ChangePasswordAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.Pim, fixture.KeyFiles,
                newPassword, newPim: 0, newKeyFiles: null);

            // Deliberately destroy the PRIMARY header region so opening can only succeed via the
            // BACKUP header - proving ChangePasswordAsync rewrote the backup with the new credentials
            // too, not just the primary.
            using (var stream = copy.File.Open(FileMode.Open, FileAccess.Write, FileShare.None))
            {
                var garbage = new byte[HeaderParser.HeaderRegionSize];
                stream.Write(garbage, 0, garbage.Length);
            }

            var container = await VeraCryptContainer.OpenAsync(copy.File, newPassword, fixture.Algorithm, fixture.HashAlgorithm, fixture.FilesystemType);
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
        public async Task ChangePasswordAsync_PrimaryAndBackupRegionsHaveIndependentSalts()
        {
            var fixture = TestContainers.AesNtfs;
            using var copy = new TemporaryContainerCopy(fixture.ContainerFile);

            await VeraCryptContainer.ChangePasswordAsync(
                copy.File, fixture.Password, fixture.Algorithm, fixture.HashAlgorithm, fixture.Pim, fixture.KeyFiles,
                "a-new-password-7", newPim: 0, newKeyFiles: null);

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
