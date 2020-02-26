using System;
using System.Linq;
using Xunit;

namespace JsonWebToken.Tests.Cryptography
{
    public abstract class ShaAlgorithmTest
    {
        protected void Verify(string input, string output)
        {
            Verify(ByteUtils.AsciiBytes(input), output);
        }

        protected void Verify(string input, string prepend, string output)
        {
            Verify(ByteUtils.AsciiBytes(input), ByteUtils.AsciiBytes(prepend), output);
        }

        protected void Verify(char input, int count, string output)
        {
            Verify(Enumerable.Repeat((byte)input, count).ToArray(), output);
        }

        protected void Verify(char input, int count, char prependInput, int prependCount, string output)
        {
            Verify(Enumerable.Repeat((byte)input, count).ToArray(), Enumerable.Repeat((byte)prependInput, prependCount).ToArray(),output);
        }

        [Fact]
        public void InvalidInput_ComputeHash()
        {
            Assert.Throws<ArgumentException>("destination", () => ComputeHash(Span<byte>.Empty, Span<byte>.Empty));
        }

        protected abstract void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination);

        protected abstract void ComputeHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination);

        protected void Verify(byte[] input, string output)
        {
            byte[] expected = ByteUtils.HexToByteArray(output);
            byte[] actual;

            // Too small
            actual = new byte[expected.Length - 1];
            Assert.Throws<ArgumentException>("destination", () => ComputeHash(input, actual));

            // Just right
            actual = new byte[expected.Length];
            ComputeHash(input, actual);
            Assert.Equal(expected, actual);

            // Bigger than needed
            actual = new byte[expected.Length + 1];
            actual[actual.Length - 1] = 42;
            ComputeHash(input, actual);
            Assert.Equal(expected, actual.AsSpan(0, expected.Length).ToArray());
            Assert.Equal(42, actual[actual.Length - 1]);
        }

        protected void Verify(byte[] input, byte[] prepend, string output)
        {
            byte[] expected = ByteUtils.HexToByteArray(output);
            byte[] actual;

            // Too small
            actual = new byte[expected.Length - 1];
            Assert.Throws<ArgumentException>("destination", () => ComputeHash(input, prepend, actual));

            // Just right
            actual = new byte[expected.Length];
            ComputeHash(input, prepend, actual);
            Assert.Equal(expected, actual);

            // Bigger than needed
            actual = new byte[expected.Length + 1];
            actual[actual.Length - 1] = 42;
            ComputeHash(input, prepend, actual);
            Assert.Equal(expected, actual.AsSpan(0, expected.Length).ToArray());
            Assert.Equal(42, actual[actual.Length - 1]);
        }

        [Fact]
        public void InvalidInput_Null()
        {
            Assert.Throws<ArgumentException>("destination", () => ComputeHash(null, null));
        }
    }
}
