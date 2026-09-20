using System;
using System.Collections.Generic;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// A PBKDF2 key stream, for one (password, salt, hash algorithm, iteration count), that grows
    /// lazily: <see cref="GetAtLeast"/> computes only as many additional blocks as needed to reach
    /// the requested length, reusing every block already computed rather than re-deriving from
    /// scratch. Exists specifically for <see cref="HeaderParser.TrySearchHashAlgorithmAsync"/>'s
    /// brute-force search over <see cref="CryptoAlgorithm"/> values for a single hash algorithm:
    /// trying the single-cipher algorithms (which need the least key material) before the cascades
    /// means the common case - a single-cipher container, found quickly - pays for only the blocks
    /// it actually needs, while a cascade found late still costs no more than deriving the full
    /// amount upfront would have (see <see cref="Pbkdf2BlockEngine"/> for why a shorter derivation
    /// is always a prefix of a longer one, which is what makes "reuse, don't recompute" safe).
    ///
    /// An earlier version of this optimization derived the maximum key length unconditionally,
    /// before trying any algorithm. That was measurably worse for the common case - a container
    /// found on the very first algorithm tried got slower, not faster, because it paid for cascade
    /// -sized key material it never used. This class exists to fix that: it costs whatever the
    /// search actually turns out to need, no more.
    /// </summary>
    internal sealed class IncrementalPbkdf2Stream : IDisposable
    {
        private readonly IPbkdf2Prf _prf;
        private readonly byte[] _salt;
        private readonly int _iterations;
        private readonly List<byte> _buffer = new List<byte>();

        public IncrementalPbkdf2Stream(IPbkdf2Prf prf, byte[] salt, int iterations)
        {
            _prf = prf;
            _salt = salt;
            _iterations = iterations;
        }

        /// <summary>
        /// The number of PBKDF2 blocks computed so far. Exposed only so tests can assert that
        /// re-requesting an already-covered length does not trigger a recomputation.
        /// </summary>
        public int BlocksComputed { get; private set; }

        /// <summary>
        /// Returns the first <paramref name="byteLength"/> bytes of the key stream, computing
        /// additional blocks only if not enough have been computed yet.
        /// </summary>
        public byte[] GetAtLeast(int byteLength)
        {
            while (_buffer.Count < byteLength)
            {
                BlocksComputed++;
                var block = Pbkdf2BlockEngine.ComputeBlock(_prf, _salt, _iterations, BlocksComputed);
                _buffer.AddRange(block);
            }

            var result = new byte[byteLength];
            _buffer.CopyTo(0, result, 0, byteLength);
            return result;
        }

        public void Dispose()
        {
            _prf.Dispose();
        }
    }
}
