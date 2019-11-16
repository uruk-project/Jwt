using System;
using System.Linq;
using Xunit;

namespace JsonWebToken.Tests.Cryptography
{
    public abstract class ShaAlgorithmTest
    {
        protected abstract Sha2 Create();

        protected void Verify(string input, string output)
        {
            Verify(ByteUtils.AsciiBytes(input), output);
        }

        protected void Verify(char input, int count, string output)
        {
            Verify(Enumerable.Repeat((byte)input, count).ToArray(), output);
        }

        [Fact]
        public void InvalidInput_ComputeHash()
        {
            Sha2 hash = Create();
            Assert.Throws<ArgumentException>("destination", () => hash.ComputeHash(Span<byte>.Empty, Span<byte>.Empty));
        }

        protected void Verify(byte[] input, string output)
        {
            byte[] expected = ByteUtils.HexToByteArray(output);
            byte[] actual;

            Sha2 hash = Create();
            // Too small
            actual = new byte[expected.Length - 1];
            Assert.Throws<ArgumentException>("destination", () => hash.ComputeHash(input, actual));

            // Just right
            actual = new byte[expected.Length];
            hash.ComputeHash(input, actual);
            Assert.Equal(expected, actual);

            // Bigger than needed
            actual = new byte[expected.Length + 1];
            actual[actual.Length - 1] = 42;
            hash.ComputeHash(input, actual);
            Assert.Equal(expected, actual.AsSpan(0, expected.Length).ToArray());
            Assert.Equal(42, actual[actual.Length - 1]);
        }

        [Fact]
        public void InvalidInput_Null()
        {
            Sha2 hash = Create();
            Assert.Throws<ArgumentException>("destination", () => hash.ComputeHash(null, null));
        }
    }
}
