using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Validates IncrementalPbkdf2Stream directly, independent of any VeraCrypt container.
    ///
    /// Two separate claims need checking, and neither implies the other:
    /// 1. Growing the stream lazily, in arbitrary steps, produces the exact same bytes as deriving
    ///    the same length in one shot (<see cref="Pbkdf2KeyDerivation.DeriveKey"/>) - i.e. the
    ///    laziness itself introduces no bug. <see cref="GetAtLeast_Sha512_MatchesOneShotDerivation"/>
    ///    and its siblings below check this for all four hash algorithms; combined with
    ///    Pbkdf2KeyDerivationLowLevelTests' own cross-checks of DeriveKey against .NET's independent
    ///    Rfc2898DeriveBytes.Pbkdf2 for SHA-512/256, this transitively proves the incremental stream
    ///    correct for those two hashes as well.
    /// 2. For Whirlpool and BLAKE2s-256, which have no independent (non-BouncyCastle) oracle
    ///    available at all, <see cref="GetAtLeast_Whirlpool_MatchesBouncyCastlesOwnPkcs5S2Generator"/>
    ///    and its BLAKE2s-256 sibling instead confirm the new BouncyCastleHmacPrf-driven block engine
    ///    reproduces exactly what BouncyCastle's own Pkcs5S2ParametersGenerator - the implementation
    ///    this library used prior to this change, and already proven correct by the Integration
    ///    suite against real VeraCrypt containers - produces for the same inputs.
    ///
    /// Accesses the internal IncrementalPbkdf2Stream/Pbkdf2PrfFactory types via reflection, matching
    /// Pbkdf2KeyDerivationLowLevelTests' own approach, so the library project does not need to grant
    /// InternalsVisibleTo.
    /// </summary>
    public class IncrementalPbkdf2StreamLowLevelTests
    {
        private static readonly byte[] Password = Encoding.UTF8.GetBytes("correct horse battery staple");
        private static readonly byte[] Salt = Encoding.UTF8.GetBytes("some-salt-value-1234567890123456");
        private const int Iterations = 5; // deliberately tiny: these are structural tests, not a PBKDF2 strength check.

        [Fact]
        public void GetAtLeast_Sha512_MatchesOneShotDerivation()
        {
            AssertIncrementalMatchesOneShot(HashAlgorithm.Sha512);
        }

        [Fact]
        public void GetAtLeast_Sha256_MatchesOneShotDerivation()
        {
            AssertIncrementalMatchesOneShot(HashAlgorithm.Sha256);
        }

        [Fact]
        public void GetAtLeast_Whirlpool_MatchesOneShotDerivation()
        {
            AssertIncrementalMatchesOneShot(HashAlgorithm.Whirlpool);
        }

        [Fact]
        public void GetAtLeast_Blake2s256_MatchesOneShotDerivation()
        {
            AssertIncrementalMatchesOneShot(HashAlgorithm.Blake2s256);
        }

        private static void AssertIncrementalMatchesOneShot(HashAlgorithm hashAlgorithm)
        {
            // Requested in small, uneven steps - not one call for the full length - so the stream
            // genuinely has to grow more than once, exercising the "reuse, don't recompute" path.
            using var stream = CreateStream(hashAlgorithm);
            GetAtLeast(stream, 20);
            GetAtLeast(stream, 40);
            var incremental = GetAtLeast(stream, 192); // 3 cascade components' worth: the largest this library ever requests.

            var oneShot = InvokeDeriveKey(hashAlgorithm, Password, Salt, Iterations, keyLengthBits: 192 * 8);

            Assert.Equal(oneShot, incremental);
        }

        [Fact]
        public void GetAtLeast_ReRequestingAlreadyCoveredLength_DoesNotRecomputeBlocks()
        {
            using var stream = CreateStream(HashAlgorithm.Sha512);

            GetAtLeast(stream, 64); // exactly one SHA-512 block (hLen = 64 bytes).
            Assert.Equal(1, GetBlocksComputed(stream));

            GetAtLeast(stream, 64); // already covered - must not compute another block.
            Assert.Equal(1, GetBlocksComputed(stream));

            GetAtLeast(stream, 32); // shorter than what's already covered - likewise.
            Assert.Equal(1, GetBlocksComputed(stream));

            GetAtLeast(stream, 128); // needs a second block now.
            Assert.Equal(2, GetBlocksComputed(stream));
        }

        [Fact]
        public void GetAtLeast_Whirlpool_MatchesBouncyCastlesOwnPkcs5S2Generator()
        {
            using var stream = CreateStream(HashAlgorithm.Whirlpool);
            var actual = GetAtLeast(stream, 192);

            var expected = DeriveWithBouncyCastleGenerator(new WhirlpoolDigest(), 192);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void GetAtLeast_Blake2s256_MatchesBouncyCastlesOwnPkcs5S2Generator()
        {
            using var stream = CreateStream(HashAlgorithm.Blake2s256);
            var actual = GetAtLeast(stream, 192);

            var expected = DeriveWithBouncyCastleGenerator(new Blake2sDigest(256), 192);

            Assert.Equal(expected, actual);
        }

        private static byte[] DeriveWithBouncyCastleGenerator(Org.BouncyCastle.Crypto.IDigest digest, int keyLengthBytes)
        {
            var generator = new Pkcs5S2ParametersGenerator(digest);
            generator.Init(Password, Salt, Iterations);
            return ((KeyParameter)generator.GenerateDerivedParameters("AES", keyLengthBytes * 8)).GetKey();
        }

        private static IDisposable CreateStream(HashAlgorithm hashAlgorithm)
        {
            var assembly = typeof(HeaderParser).Assembly;

            var prfFactoryType = FindType(assembly, "Pbkdf2PrfFactory");
            var createMethod = prfFactoryType.GetMethod("Create", BindingFlags.Public | BindingFlags.Static)
                ?? throw new InvalidOperationException("Pbkdf2PrfFactory.Create method not found.");
            var prf = Invoke(createMethod, null, hashAlgorithm, Password);

            var streamType = FindType(assembly, "IncrementalPbkdf2Stream");
            var constructor = streamType.GetConstructors(BindingFlags.Public | BindingFlags.Instance)[0];
            return (IDisposable)constructor.Invoke(new object[] { prf, Salt, Iterations });
        }

        private static byte[] GetAtLeast(IDisposable stream, int byteLength)
        {
            var method = stream.GetType().GetMethod("GetAtLeast", BindingFlags.Public | BindingFlags.Instance)
                ?? throw new InvalidOperationException("IncrementalPbkdf2Stream.GetAtLeast method not found.");
            return (byte[])Invoke(method, stream, byteLength);
        }

        private static int GetBlocksComputed(IDisposable stream)
        {
            var property = stream.GetType().GetProperty("BlocksComputed", BindingFlags.Public | BindingFlags.Instance)
                ?? throw new InvalidOperationException("IncrementalPbkdf2Stream.BlocksComputed property not found.");
            return (int)property.GetValue(stream)!;
        }

        private static Type FindType(Assembly assembly, string name)
        {
            return Array.Find(assembly.GetTypes(), t => t.Name == name)
                ?? throw new InvalidOperationException($"{name} type not found.");
        }

        private static object Invoke(MethodInfo method, object? target, params object[] args)
        {
            try
            {
                return method.Invoke(target, args)!;
            }
            catch (TargetInvocationException ex) when (ex.InnerException != null)
            {
                throw ex.InnerException;
            }
        }

        private static byte[] InvokeDeriveKey(HashAlgorithm hashAlgorithm, byte[] passwordBytes, byte[] salt, int iterations, int keyLengthBits)
        {
            var type = FindType(typeof(HeaderParser).Assembly, "Pbkdf2KeyDerivation");
            var method = type.GetMethod("DeriveKey", BindingFlags.Public | BindingFlags.Static)
                ?? throw new InvalidOperationException("Pbkdf2KeyDerivation.DeriveKey method not found.");
            return (byte[])Invoke(method, null, hashAlgorithm, passwordBytes, salt, iterations, keyLengthBits);
        }
    }
}
