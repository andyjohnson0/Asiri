using System;
using System.Reflection;
using System.Text;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Validates the internal CRC-32 implementation directly against the standard CRC-32/ISO-HDLC
    /// check value, independent of any VeraCrypt container. Accessed via reflection so the library
    /// project does not need to expose it or grant InternalsVisibleTo.
    /// </summary>
    public class Crc32LowLevelTests
    {
        [Fact]
        public void Compute_StandardCheckValue_MatchesKnownResult()
        {
            // The well-known CRC-32/ISO-HDLC check value: CRC32("123456789") == 0xCBF43926.
            var input = Encoding.ASCII.GetBytes("123456789");

            var result = InvokeCompute(input, 0, input.Length);

            Assert.Equal(0xCBF43926u, result);
        }

        [Fact]
        public void Compute_OfSubRange_OnlyCoversRequestedBytes()
        {
            var input = Encoding.ASCII.GetBytes("XX123456789YY");

            var result = InvokeCompute(input, 2, 9);

            Assert.Equal(0xCBF43926u, result);
        }

        private static uint InvokeCompute(byte[] data, int offset, int length)
        {
            var type = Array.Find(typeof(HeaderParser).Assembly.GetTypes(), t => t.Name == "Crc32")
                       ?? throw new InvalidOperationException("Crc32 type not found.");
            var method = type.GetMethod("Compute", BindingFlags.Public | BindingFlags.Static)
                       ?? throw new InvalidOperationException("Crc32.Compute method not found.");
            return (uint)method.Invoke(null, new object[] { data, offset, length })!;
        }
    }
}
