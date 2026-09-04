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
        /// Computes the CRC-32 checksum of a region of a byte array.
        /// </summary>
        public static uint Compute(byte[] data, int offset, int length)
        {
            var crc = 0xFFFFFFFF;
            for (var i = offset; i < offset + length; i++)
            {
                crc = _table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
            }
            return crc ^ 0xFFFFFFFF;
        }
    }
}
