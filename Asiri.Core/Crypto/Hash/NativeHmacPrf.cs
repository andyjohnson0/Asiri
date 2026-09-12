using System.Security.Cryptography;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// <see cref="IPbkdf2Prf"/> backed by one of .NET's own <see cref="HMAC"/> classes
    /// (<see cref="HMACSHA512"/>/<see cref="HMACSHA256"/>), used for SHA-512 and SHA-256 - see
    /// <see cref="Pbkdf2PrfFactory"/>. Measured roughly 1.7x (SHA-512) to 4.5x (SHA-256) faster than
    /// BouncyCastle's managed implementation for a 500,000-iteration derivation, on account of
    /// .NET's HMAC classes being backed by the OS's own crypto provider rather than a pure-managed
    /// one.
    /// </summary>
    internal sealed class NativeHmacPrf : IPbkdf2Prf
    {
        private readonly HMAC _hmac;

        /// <summary>Takes ownership of <paramref name="hmac"/>: disposed when this instance is.</summary>
        public NativeHmacPrf(HMAC hmac)
        {
            _hmac = hmac;
        }

        public int HashLengthBytes => _hmac.HashSize / 8;

        public byte[] ComputeHmac(byte[] message)
        {
            return _hmac.ComputeHash(message);
        }

        public void Dispose()
        {
            _hmac.Dispose();
        }
    }
}
