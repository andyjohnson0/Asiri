using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// <see cref="IPbkdf2Prf"/> backed by BouncyCastle's generic <see cref="HMac"/> wrapper around
    /// any <see cref="IDigest"/>, used for Whirlpool and BLAKE2s-256 - the two hash algorithms .NET
    /// has no built-in support for; see <see cref="Pbkdf2PrfFactory"/>. This reuses BouncyCastle's
    /// own HMAC construction (the same one its <c>Pkcs5S2ParametersGenerator</c> already relies on
    /// internally) rather than reimplementing HMAC from scratch.
    /// </summary>
    internal sealed class BouncyCastleHmacPrf : IPbkdf2Prf
    {
        private readonly HMac _hmac;

        public BouncyCastleHmacPrf(IDigest digest, byte[] key)
        {
            _hmac = new HMac(digest);
            _hmac.Init(new KeyParameter(key));
        }

        public int HashLengthBytes => _hmac.GetMacSize();

        public byte[] ComputeHmac(byte[] message)
        {
            _hmac.BlockUpdate(message, 0, message.Length);
            var output = new byte[_hmac.GetMacSize()];
            _hmac.DoFinal(output, 0);
            return output;
        }

        public void Dispose()
        {
            // HMac holds no unmanaged/disposable resources of its own.
        }
    }
}
