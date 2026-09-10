using System;
using System.Collections.Generic;
using System.IO;

namespace uk.andyjohnson.Asiri.Core.Crypto
{
    /// <summary>
    /// Mixes one or more VeraCrypt keyfiles into a password's byte representation, per VeraCrypt's
    /// own algorithm - verified against VeraCrypt's own source (Common/Keyfiles.c's KeyFilesApply and
    /// KeyFileProcess, Common/Keyfiles.h, Common/Password.h) rather than assumed.
    ///
    /// For each keyfile, in the order supplied, up to <see cref="MaxBytesPerKeyfile"/> bytes are read
    /// (a per-keyfile cap, not shared across keyfiles). Every byte read advances a running,
    /// never-finalized CRC-32 register (<see cref="Crc32.UpdateByte"/>); the register's four
    /// big-endian bytes are added (mod 256, wrapping) onto a pool of <see cref="PoolSizeLegacy"/> or
    /// <see cref="PoolSize"/> bytes - whichever the password's length selects - at a write position
    /// that cycles through the pool and restarts at 0 for every new keyfile, so multiple keyfiles
    /// accumulate into the same pool.
    ///
    /// The pool is then mixed into the password: positions within the original password's length are
    /// added (mod 256) onto the existing password byte; positions beyond it are set directly from the
    /// pool, extending the password up to the pool's size. An empty password is fully supported - the
    /// mixed result becomes the pool's contents verbatim, VeraCrypt's own keyfile-only mode.
    /// </summary>
    internal static class KeyfileMixer
    {
        /// <summary>The pool size used when the password is <see cref="MaxLegacyPasswordLength"/> bytes or shorter.</summary>
        private const int PoolSizeLegacy = 64;

        /// <summary>The pool size used when the password is longer than <see cref="MaxLegacyPasswordLength"/> bytes.</summary>
        private const int PoolSize = 128;

        private const int MaxLegacyPasswordLength = 64;

        /// <summary>The maximum number of bytes read from a single keyfile.</summary>
        private const int MaxBytesPerKeyfile = 1024 * 1024;

        private const int ReadBufferSize = 64 * 1024;

        /// <summary>
        /// Mixes <paramref name="keyFiles"/> into <paramref name="passwordBytes"/>, returning the
        /// mixed result as a new array. If <paramref name="keyFiles"/> is null or empty,
        /// <paramref name="passwordBytes"/> is returned unchanged - matching VeraCrypt's own
        /// no-keyfiles-supplied behaviour.
        /// </summary>
        public static byte[] Apply(byte[] passwordBytes, IEnumerable<FileInfo> keyFiles)
        {
            if (passwordBytes == null)
            {
                throw new ArgumentNullException(nameof(passwordBytes));
            }
            if (keyFiles == null)
            {
                return passwordBytes;
            }

            var keyFileList = new List<FileInfo>();
            foreach (var keyFile in keyFiles)
            {
                if (keyFile == null)
                {
                    throw new ArgumentException("keyFiles must not contain a null entry.", nameof(keyFiles));
                }
                keyFileList.Add(keyFile);
            }
            if (keyFileList.Count == 0)
            {
                return passwordBytes;
            }

            var poolSize = passwordBytes.Length <= MaxLegacyPasswordLength ? PoolSizeLegacy : PoolSize;
            var pool = new byte[poolSize];
            foreach (var keyFile in keyFileList)
            {
                MixKeyFileIntoPool(keyFile, pool);
            }

            var mixed = new byte[Math.Max(passwordBytes.Length, poolSize)];
            Buffer.BlockCopy(passwordBytes, 0, mixed, 0, passwordBytes.Length);
            for (var i = 0; i < poolSize; i++)
            {
                mixed[i] = i < passwordBytes.Length
                    ? unchecked((byte)(mixed[i] + pool[i]))
                    : pool[i];
            }
            return mixed;
        }

        private static void MixKeyFileIntoPool(FileInfo keyFile, byte[] pool)
        {
            FileStream stream;
            try
            {
                stream = new FileStream(keyFile.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is ArgumentNullException))
            {
                throw new InvalidOperationException($"Unable to open keyfile: {keyFile.FullName}", ex);
            }

            using (stream)
            {
                var buffer = new byte[ReadBufferSize];
                var crc = Crc32.InitialValue;
                var writePos = 0;
                var totalRead = 0;

                int bytesRead;
                while (totalRead < MaxBytesPerKeyfile && (bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    for (var i = 0; i < bytesRead && totalRead < MaxBytesPerKeyfile; i++)
                    {
                        crc = Crc32.UpdateByte(crc, buffer[i]);

                        AddByteToPool(pool, ref writePos, (byte)(crc >> 24));
                        AddByteToPool(pool, ref writePos, (byte)(crc >> 16));
                        AddByteToPool(pool, ref writePos, (byte)(crc >> 8));
                        AddByteToPool(pool, ref writePos, (byte)crc);

                        totalRead++;
                    }
                }

                if (totalRead == 0)
                {
                    throw new ArgumentException($"Keyfile is empty: {keyFile.FullName}", nameof(keyFile));
                }
            }
        }

        private static void AddByteToPool(byte[] pool, ref int writePos, byte value)
        {
            pool[writePos] = unchecked((byte)(pool[writePos] + value));
            writePos++;
            if (writePos >= pool.Length)
            {
                writePos = 0;
            }
        }
    }
}
