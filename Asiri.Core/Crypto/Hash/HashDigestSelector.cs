using System;
using Org.BouncyCastle.Crypto;
using uk.andyjohnson.Asiri.Core.Crypto;

namespace uk.andyjohnson.Asiri.Core.Crypto.Hash
{
    /// <summary>
    /// Selects the BouncyCastle digest to use as the PBKDF2 PRF, per <see cref="HashAlgorithm"/>.
    /// Mirrors <see cref="Crypto.XtsCipherSelector"/>'s role for <see cref="CryptoAlgorithm"/>.
    /// </summary>
    internal static class HashDigestSelector
    {
        public static IDigest Create(HashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.Sha512:
                    return Sha512DigestFactory.Create();
                case HashAlgorithm.Sha256:
                    return Sha256DigestFactory.Create();
                case HashAlgorithm.Whirlpool:
                    return WhirlpoolDigestFactory.Create();
                case HashAlgorithm.Blake2s256:
                    return Blake2s256DigestFactory.Create();
                default:
                    throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}.", nameof(hashAlgorithm));
            }
        }
    }
}
