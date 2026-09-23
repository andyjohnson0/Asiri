using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Tests for PIM (Personal Iterations Multiplier) support: the PBKDF2 iteration-count formula
    /// itself, and both OpenAsync overloads' end-to-end behaviour against real VeraCrypt containers
    /// created with a non-default PIM. VeraCrypt does not store the PIM in the header - like the
    /// password, it must be supplied by the caller, and (unlike the encryption/hash algorithms) is
    /// never searched for - so the negative cases here use a single wrong guess, not an exhaustive
    /// search, and none of these tests need the Integration category.
    /// </summary>
    public class PimTests
    {
        /// <summary>
        /// Validates HeaderParser's private iteration-count formula directly against VeraCrypt's own
        /// formula (Common/Pkcs5.c, get_pkcs5_iteration_count, non-boot case), independent of any
        /// container. 485 is included because VeraCrypt's own mount dialog displays it as PIM 0's
        /// "equivalent" value - confirmed against a real dialog, not just the source reading.
        /// </summary>
        [Theory]
        [InlineData(0, 500000)]
        [InlineData(1, 16000)]
        [InlineData(5, 20000)]
        [InlineData(20, 35000)]
        [InlineData(485, 500000)]
        public void GetPbkdf2IterationCount_MatchesVeraCryptFormula(int pim, int expectedIterations)
        {
            var method = typeof(HeaderParser).GetMethod("GetPbkdf2IterationCount", BindingFlags.NonPublic | BindingFlags.Static)
                       ?? throw new InvalidOperationException("HeaderParser.GetPbkdf2IterationCount method not found.");
            var actual = (int)method.Invoke(null, new object[] { pim })!;

            Assert.Equal(expectedIterations, actual);
        }

        [Theory]
        [MemberData(nameof(PimFixtures))]
        public async Task OpenAsync_ExplicitParameters_WithCorrectPim_OpensContainer(TestContainers.ContainerFixture fixture)
        {
            var container = await fixture.OpenAsync();
            try
            {
                var testTxt = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await testTxt.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Theory]
        [MemberData(nameof(PimFixtures))]
        public async Task OpenAsync_ExplicitParameters_WithWrongPim_ThrowsInvalidOperationException(TestContainers.ContainerFixture fixture)
        {
            // Omitting pim defaults to 0 - a real PIM was used to create these containers, so this is
            // a genuinely wrong PIM, not just an unspecified one. A single (correct algorithm, correct
            // hash, wrong PIM) attempt costs one PBKDF2 call, not a search - this stays cheap.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm }));
        }

        [Fact]
        public async Task OpenAsync_ExplicitParameters_NegativePim_ThrowsArgumentException()
        {
            var fixture = TestContainers.AesPim5ExFat;
            var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Algorithm = fixture.Algorithm, HashAlgorithm = fixture.HashAlgorithm, Pim = -1 }));

            Assert.Equal("options", exception.ParamName);
        }

        /// <summary>
        /// Proves the brute-force, password-only OpenAsync overload correctly threads the supplied
        /// PIM through the (algorithm, hash) search, rather than silently ignoring it or defaulting
        /// to 0 internally - if it did, none of the 40 combinations tried would validate against a
        /// non-default-PIM container. Both fixtures use AES, first in the CryptoAlgorithm enum, and
        /// SHA-512/Whirlpool are 1st/3rd in HashAlgorithm, so this resolves in only a few attempts -
        /// no need for the Integration category.
        /// </summary>
        [Theory]
        [MemberData(nameof(PimFixtures))]
        public async Task OpenAsync_PasswordOnly_WithCorrectPim_DetectsAlgorithmAndOpensContainer(TestContainers.ContainerFixture fixture)
        {
            var container = (await VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Pim = fixture.Pim })).Container;
            try
            {
                Assert.Equal(fixture.Algorithm, container.Algorithm);
                Assert.Equal(fixture.HashAlgorithm, container.HashAlgorithm);
                var testTxt = await container.Root.GetFileAsync("test.txt");
                Assert.Equal("Hello, world!", await testTxt.ReadAllTextAsync());
            }
            finally
            {
                container.Close();
            }
        }

        [Fact]
        public async Task OpenAsync_PasswordOnly_NegativePim_ThrowsArgumentException()
        {
            var fixture = TestContainers.AesPim5ExFat;
            var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
                VeraCryptContainer.OpenAsync(fixture.ContainerFile, fixture.Password, new OpenOptions { Pim = -1 }));

            Assert.Equal("options", exception.ParamName);
        }

        public static IEnumerable<object[]> PimFixtures()
        {
            yield return new object[] { TestContainers.AesPim5ExFat };
            yield return new object[] { TestContainers.AesPim20ExFat };
        }
    }
}
