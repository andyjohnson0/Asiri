using System;

namespace uk.andyjohnson.Asiri.Core
{
    /// <summary>
    /// Computes the CRC-32 checksum used to validate VeraCrypt volume header fields.
    /// </summary>
    internal static class Crc32
    {
        private static readonly uint[] _table = BuildTable();

        private static uint[] BuildTable()
        {
            var table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                var c = i;
                for (var k = 0; k < 8; k++)
                {
                    c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
                }
                table[i] = c;
            }
            return table;
        }

        /// <summary>
        /// The starting value of the running CRC-32 register, before any bytes are processed.
        /// </summary>
        public const uint InitialValue = 0xFFFFFFFF;

        /// <summary>
        /// Computes the CRC-32 checksum of a region of a byte array.
        /// </summary>
        public static uint Compute(byte[] data, int offset, int length)
        {
            var crc = InitialValue;
            for (var i = offset; i < offset + length; i++)
            {
                crc = UpdateByte(crc, data[i]);
            }
            return crc ^ InitialValue;
        }

        /// <summary>
        /// Advances a running CRC-32 register by one byte, without finalizing it (no final XOR).
        /// Exposed for VeraCrypt's keyfile pool-mixing algorithm (see <see cref="Crypto.KeyfileMixer"/>),
        /// which uses the raw intermediate register value after each byte as a mixing source, not as
        /// a finished checksum - unlike <see cref="Compute"/>, which finalizes the standard way.
        /// </summary>
        public static uint UpdateByte(uint crc, byte value)
        {
            return _table[(crc ^ value) & 0xFF] ^ (crc >> 8);
        }
    }
}
