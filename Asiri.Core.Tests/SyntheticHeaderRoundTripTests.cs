using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Builds a synthetic VeraCrypt-format volume header from scratch, using an AES-XTS and
    /// PBKDF2-HMAC-SHA512 implementation that is entirely independent of Asiri.Core (.NET's built-in
    /// Aes and Rfc2898DeriveBytes rather than the library's BouncyCastle-based code), and confirms
    /// that the real, public HeaderParser.Parse correctly decodes it. This is a cross-check, not two
    /// copies of the same code agreeing with each other: it pins down the exact header field
    /// offsets, big-endian field encoding (including both CRC-32 fields), PBKDF2 parameters, and
    /// AES-XTS key ordering end-to-end through the public API.
    ///
    /// Field offsets below (relative to the start of the 448-byte encrypted header, i.e. absolute
    /// file offset 64, since the header is preceded by a 64-byte unencrypted salt) are taken from
    /// the official VeraCrypt Volume Format Specification
    /// (https://veracrypt.io/en/VeraCrypt%20Volume%20Format%20Specification.html):
    ///
    ///   0   4   Magic "VERA"
    ///   4   2   Header format version
    ///   6   2   Minimum program version required
    ///   8   4   CRC-32 of bytes 192-447 (the master key area), big-endian
    ///   12  16  Reserved
    ///   28  8   Hidden volume size
    ///   36  8   Volume size
    ///   44  8   Master key scope start offset
    ///   52  8   Encrypted area size
    ///   60  4   Flags
    ///   64  4   Sector size
    ///   68  120 Reserved
    ///   188 4   CRC-32 of bytes 0-187, big-endian
    ///   192 32  Primary (data) master key
    ///   224 32  Secondary (tweak) master key
    /// </summary>
    public class SyntheticHeaderRoundTripTests
    {
        private const string Password = "correct horse battery staple";
        private const int Pbkdf2Iterations = 500000;
        private const long VolumeSize = 5 * 1024 * 1024;
        private const int SectorSize = 512;

        [Fact]
        public async Task ParseAsync_SyntheticHeaderBuiltFromSpecOffsets_DecodesCorrectly()
        {
            var rnd = new Random(12345);
            var salt = RandomBytes(rnd, 64);
            var masterKey = RandomBytes(rnd, 32);
            var secondaryKey = RandomBytes(rnd, 32);

            var region = BuildHeaderRegion(salt, masterKey, secondaryKey, swapKeys: false);
            using var tempFile = new TempContainerFile(region);

            var header = await HeaderParser.ParseAsync(tempFile.Path, Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512);

            Assert.Equal("VERA", header.Magic);
            Assert.Equal(5, header.Version);
            Assert.Equal(SectorSize, header.SectorSize);
            Assert.Equal(VolumeSize, header.VolumeSize);
            Assert.True(header.CrcValid);
            Assert.False(header.FromBackup);
            Assert.Equal(masterKey, header.MasterKey);
            Assert.Equal(secondaryKey, header.SecondaryKey);
        }

        [Fact]
        public async Task ParseAsync_SyntheticHeaderWithKey1AndKey2Swapped_FailsToDecode()
        {
            // If HeaderParser split the derived PBKDF2 output into a data key and tweak key in the
            // opposite order to this test's independent encoder, the preceding "correct order" test
            // could pass by symmetry and hide a real bug. This variant swaps the header encryption
            // key halves while encrypting, and confirms HeaderParser - which always treats the first
            // 32 derived bytes as the data key and the next 32 as the tweak key - then fails to
            // decode it, proving the positive test above is actually sensitive to key order.
            var rnd = new Random(54321);
            var salt = RandomBytes(rnd, 64);
            var masterKey = RandomBytes(rnd, 32);
            var secondaryKey = RandomBytes(rnd, 32);

            var region = BuildHeaderRegion(salt, masterKey, secondaryKey, swapKeys: true);
            using var tempFile = new TempContainerFile(region);

            await Assert.ThrowsAsync<InvalidOperationException>(() => HeaderParser.ParseAsync(tempFile.Path, Password, CryptoAlgorithm.Aes, HashAlgorithm.Sha512));
        }

        private static byte[] RandomBytes(Random rnd, int count)
        {
            var b = new byte[count];
            rnd.NextBytes(b);
            return b;
        }

        private static byte[] BuildHeaderRegion(byte[] salt, byte[] masterKey, byte[] secondaryKey, bool swapKeys)
        {
            var d = new byte[448];
            Encoding.ASCII.GetBytes("VERA").CopyTo(d, 0);
            WriteUInt16BE(d, 4, 5);
            WriteUInt16BE(d, 6, 0x0108);
            WriteInt64BE(d, 28, 0);
            WriteInt64BE(d, 36, VolumeSize);
            WriteInt64BE(d, 44, 131072);
            WriteInt64BE(d, 52, VolumeSize - 131072 - 131072);
            WriteUInt32BE(d, 60, 0);
            WriteUInt32BE(d, 64, SectorSize);
            masterKey.CopyTo(d, 192);
            secondaryKey.CopyTo(d, 224);

            WriteUInt32BE(d, 8, Crc32Ieee(d, 192, 256));
            WriteUInt32BE(d, 188, Crc32Ieee(d, 0, 188));

            var headerKey = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(Password), salt, Pbkdf2Iterations, HashAlgorithmName.SHA512, 64);
            var hk1 = headerKey[..32];
            var hk2 = headerKey[32..];
            if (swapKeys)
            {
                (hk1, hk2) = (hk2, hk1);
            }

            var encrypted = XtsEncryptIndependent(d, hk1, hk2);

            var region = new byte[512];
            salt.CopyTo(region, 0);
            encrypted.CopyTo(region, 64);
            return region;
        }

        private static void WriteUInt16BE(byte[] d, int offset, int value)
        {
            d[offset] = (byte)(value >> 8);
            d[offset + 1] = (byte)value;
        }

        private static void WriteUInt32BE(byte[] d, int offset, long value)
        {
            d[offset] = (byte)(value >> 24);
            d[offset + 1] = (byte)(value >> 16);
            d[offset + 2] = (byte)(value >> 8);
            d[offset + 3] = (byte)value;
        }

        private static void WriteInt64BE(byte[] d, int offset, long value)
        {
            for (var i = 0; i < 8; i++)
            {
                d[offset + i] = (byte)(value >> (56 - 8 * i));
            }
        }

        private static uint Crc32Ieee(byte[] d, int offset, int length)
        {
            var crc = 0xFFFFFFFFu;
            for (var i = offset; i < offset + length; i++)
            {
                crc ^= d[i];
                for (var b = 0; b < 8; b++)
                {
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
                }
            }
            return crc ^ 0xFFFFFFFFu;
        }

        /// <summary>
        /// A from-scratch AES-XTS-256 encryptor using .NET's built-in Aes class in ECB mode -
        /// deliberately independent of the BouncyCastle-based implementation under test - so that a
        /// round trip through the real HeaderParser.Parse is a meaningful cross-check.
        /// </summary>
        private static byte[] XtsEncryptIndependent(byte[] plain, byte[] dataKey, byte[] tweakKey)
        {
            using var dataAes = CreateEcbAes(dataKey);
            using var tweakAes = CreateEcbAes(tweakKey);
            using var dataTransform = dataAes.CreateEncryptor();
            using var tweakTransform = tweakAes.CreateEncryptor();

            var tweakInput = new byte[16]; // data-unit sequence number 0
            var t = new byte[16];
            tweakTransform.TransformBlock(tweakInput, 0, 16, t, 0);

            var output = new byte[plain.Length];
            var xored = new byte[16];
            var encrypted = new byte[16];
            var blocks = plain.Length / 16;
            for (var i = 0; i < blocks; i++)
            {
                var off = i * 16;
                for (var j = 0; j < 16; j++)
                {
                    xored[j] = (byte)(plain[off + j] ^ t[j]);
                }

                dataTransform.TransformBlock(xored, 0, 16, encrypted, 0);

                for (var j = 0; j < 16; j++)
                {
                    output[off + j] = (byte)(encrypted[j] ^ t[j]);
                }

                var carry = 0;
                for (var k = 0; k < 16; k++)
                {
                    var nextCarry = (t[k] >> 7) & 1;
                    t[k] = (byte)((t[k] << 1) | carry);
                    carry = nextCarry;
                }
                if (carry != 0)
                {
                    t[0] ^= 0x87;
                }
            }
            return output;
        }

        private static Aes CreateEcbAes(byte[] key)
        {
            var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            return aes;
        }

        private sealed class TempContainerFile : IDisposable
        {
            public string Path { get; }

            public TempContainerFile(byte[] headerRegion)
            {
                Path = System.IO.Path.GetTempFileName();
                using var fs = new FileStream(Path, FileMode.Create);
                fs.SetLength(VolumeSize);
                fs.Write(headerRegion, 0, headerRegion.Length);
            }

            public void Dispose()
            {
                File.Delete(Path);
            }
        }
    }
}
