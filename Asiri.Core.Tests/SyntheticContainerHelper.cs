using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Builds synthetic VeraCrypt-format containers for Stage 2 sector-decryption tests, using an
    /// AES-XTS / PBKDF2-HMAC-SHA512 implementation independent of Asiri.Core (.NET's built-in Aes and
    /// Rfc2898DeriveBytes rather than the library's BouncyCastle-based code). Decrypting the result
    /// through the real, public HeaderParser.Parse and SectorDecryptor is therefore a meaningful
    /// cross-check, not two copies of the same code agreeing with each other.
    /// </summary>
    internal static class SyntheticContainerHelper
    {
        private const int Pbkdf2Iterations = 500000;
        private const string HeaderPassword = "synthetic-test-password";

        public sealed class Container : IDisposable
        {
            public string Path { get; }
            public string Password => HeaderPassword;
            public byte[] MasterKey { get; }
            public byte[] SecondaryKey { get; }

            internal Container(string path, byte[] masterKey, byte[] secondaryKey)
            {
                Path = path;
                MasterKey = masterKey;
                SecondaryKey = secondaryKey;
            }

            public void Dispose()
            {
                File.Delete(Path);
            }
        }

        /// <summary>
        /// Creates a temporary file of the given total length, containing only a valid, CRC-checked
        /// primary volume header (with randomly-generated master keys and the given layout fields).
        /// No sector data is written; use <see cref="WriteEncryptedData"/> to place known-plaintext
        /// sectors afterwards. On filesystems that support sparse files (e.g. NTFS), a large
        /// fileLength allocates almost instantly.
        /// </summary>
        public static Container CreateContainer(
            long fileLength, int sectorSize, long masterKeyScopeOffset, long encryptedAreaSize, int seed)
        {
            var rnd = new Random(seed);
            var salt = RandomBytes(rnd, 64);
            var masterKey = RandomBytes(rnd, 32);
            var secondaryKey = RandomBytes(rnd, 32);

            var headerRegion = BuildHeaderRegion(salt, sectorSize, masterKeyScopeOffset, encryptedAreaSize, masterKey, secondaryKey);

            var path = Path.GetTempFileName();
            using (var fs = new FileStream(path, FileMode.Create))
            {
                fs.SetLength(fileLength);
                fs.Write(headerRegion, 0, headerRegion.Length);
            }

            return new Container(path, masterKey, secondaryKey);
        }

        /// <summary>
        /// Encrypts <paramref name="plaintext"/> (whose length must be a multiple of 512 bytes) with
        /// the container's master keys and writes it at the given absolute file offset. Each 512-byte
        /// chunk is independently tweaked using data-unit sequence number (fileOffset + chunkOffset)
        /// / 512 - i.e. counted from the start of the file, not from the start of the encrypted data
        /// area - matching the convention the real container was empirically confirmed to use.
        /// </summary>
        public static void WriteEncryptedData(Container container, long fileOffset, byte[] plaintext)
        {
            WriteEncryptedData(container, fileOffset, dataUnitBaseOffset: fileOffset, plaintext);
        }

        /// <summary>
        /// As <see cref="WriteEncryptedData(Container, long, byte[])"/>, but the data-unit sequence
        /// numbers are computed from <paramref name="dataUnitBaseOffset"/> instead of
        /// <paramref name="fileOffset"/>, letting a test deliberately encrypt bytes as if they lived
        /// at a different file position than where they are actually written. Used to construct a
        /// negative test for the data-unit numbering convention.
        /// </summary>
        public static void WriteEncryptedData(Container container, long fileOffset, long dataUnitBaseOffset, byte[] plaintext)
        {
            if (plaintext.Length % 512 != 0)
            {
                throw new ArgumentException("Plaintext length must be a multiple of 512 bytes.", nameof(plaintext));
            }

            var ciphertext = new byte[plaintext.Length];
            var chunks = plaintext.Length / 512;
            for (var i = 0; i < chunks; i++)
            {
                var chunkOffset = i * 512;
                var chunk = new byte[512];
                Buffer.BlockCopy(plaintext, chunkOffset, chunk, 0, 512);

                var dataUnitNumber = (dataUnitBaseOffset + chunkOffset) / 512;
                var encryptedChunk = XtsEncrypt(chunk, container.MasterKey, container.SecondaryKey, dataUnitNumber);

                Buffer.BlockCopy(encryptedChunk, 0, ciphertext, chunkOffset, 512);
            }

            using var fs = new FileStream(container.Path, FileMode.Open, FileAccess.Write);
            fs.Seek(fileOffset, SeekOrigin.Begin);
            fs.Write(ciphertext, 0, ciphertext.Length);
        }

        private static byte[] RandomBytes(Random rnd, int count)
        {
            var b = new byte[count];
            rnd.NextBytes(b);
            return b;
        }

        private static byte[] BuildHeaderRegion(
            byte[] salt, int sectorSize, long masterKeyScopeOffset, long encryptedAreaSize, byte[] masterKey, byte[] secondaryKey)
        {
            var d = new byte[448];
            Encoding.ASCII.GetBytes("VERA").CopyTo(d, 0);
            WriteUInt16BE(d, 4, 5);
            WriteUInt16BE(d, 6, 0x0108);
            WriteInt64BE(d, 28, 0);
            WriteInt64BE(d, 36, masterKeyScopeOffset + encryptedAreaSize);
            WriteInt64BE(d, 44, masterKeyScopeOffset);
            WriteInt64BE(d, 52, encryptedAreaSize);
            WriteUInt32BE(d, 60, 0);
            WriteUInt32BE(d, 64, sectorSize);
            masterKey.CopyTo(d, 192);
            secondaryKey.CopyTo(d, 224);

            WriteUInt32BE(d, 8, Crc32Ieee(d, 192, 256));
            WriteUInt32BE(d, 188, Crc32Ieee(d, 0, 188));

            var headerKey = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(HeaderPassword), salt, Pbkdf2Iterations, HashAlgorithmName.SHA512, 64);
            var hk1 = headerKey[..32];
            var hk2 = headerKey[32..];

            var encryptedHeader = XtsEncrypt(d, hk1, hk2, dataUnitNumber: 0);

            var region = new byte[512];
            salt.CopyTo(region, 0);
            encryptedHeader.CopyTo(region, 64);
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
        /// A from-scratch AES-XTS encryptor (single data unit, arbitrary length treated as one
        /// continuous tweak-doubling sequence starting at dataUnitNumber) using .NET's built-in Aes
        /// class in ECB mode - deliberately independent of the BouncyCastle-based implementation
        /// under test.
        /// </summary>
        private static byte[] XtsEncrypt(byte[] plain, byte[] dataKey, byte[] tweakKey, long dataUnitNumber)
        {
            using var dataAes = CreateEcbAes(dataKey);
            using var tweakAes = CreateEcbAes(tweakKey);
            using var dataTransform = dataAes.CreateEncryptor();
            using var tweakTransform = tweakAes.CreateEncryptor();

            var tweakInput = new byte[16];
            var dataUnitBytes = BitConverter.GetBytes(dataUnitNumber);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(dataUnitBytes);
            }
            Buffer.BlockCopy(dataUnitBytes, 0, tweakInput, 0, dataUnitBytes.Length);

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
    }
}
