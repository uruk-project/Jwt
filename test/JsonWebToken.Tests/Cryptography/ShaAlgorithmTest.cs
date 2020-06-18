using System;
using System.Linq;
using Xunit;

namespace JsonWebToken.Tests.Cryptography
{
    public abstract class ShaAlgorithmTest
    {
        public abstract Sha2 Sha { get; }

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
            Verify(Enumerable.Repeat((byte)input, count).ToArray(), Enumerable.Repeat((byte)prependInput, prependCount).ToArray(), output);
        }

        [Fact]
        public void InvalidInput_ComputeHash()
        {
            Assert.Throws<ArgumentException>("destination", () => Sha.ComputeHash(Span<byte>.Empty, Span<byte>.Empty));
        }

        protected void Verify(ReadOnlySpan<byte> input, string output)
        {
            byte[] expected = ByteUtils.HexToByteArray(output);
            byte[] actual;

            // Too small
            actual = new byte[expected.Length - 1];
            try
            {
                Sha.ComputeHash(input, actual);
            }
            catch (ArgumentException e)
            {
                Assert.Equal("destination", e.ParamName);
            }

            // Just right
            actual = new byte[expected.Length];
            Sha.ComputeHash(input, actual);
            Assert.Equal(expected, actual);

            // Bigger than needed
            actual = new byte[expected.Length + 1];
            actual[actual.Length - 1] = 42;
            Sha.ComputeHash(input, actual);
            Assert.Equal(expected, actual.AsSpan(0, expected.Length).ToArray());
            Assert.Equal(42, actual[actual.Length - 1]);
        }

        protected void Verify(byte[] input, byte[] prepend, string output)
        {
            byte[] expected = ByteUtils.HexToByteArray(output);
            byte[] actual;

            // Too small
            actual = new byte[expected.Length - 1];
            Assert.Throws<ArgumentException>("destination", () => Sha.ComputeHash(input, prepend, actual));

            // Just right
            actual = new byte[expected.Length];
            Sha.ComputeHash(input, prepend, actual);
            Assert.Equal(expected, actual);

            // Bigger than needed
            actual = new byte[expected.Length + 1];
            actual[actual.Length - 1] = 42;
            Sha.ComputeHash(input, prepend, actual);
            Assert.Equal(expected, actual.AsSpan(0, expected.Length).ToArray());
            Assert.Equal(42, actual[actual.Length - 1]);
        }

        [Fact]
        public void InvalidInput_Null_ThrowArgumentException()
        {
            Assert.Throws<ArgumentException>("destination", () => Sha.ComputeHash(null, null));
        }

        [Fact]
        public void Hash_InPlace_Success()
        {
            var source = new byte[Sha.HashSize];
            var source2 = new byte[Sha.HashSize];
            var destination = new byte[Sha.HashSize];

            Sha.ComputeHash(source, destination);
            Sha.ComputeHash(source2, source2);

            Assert.Equal(source2, destination);

            Array.Clear(source2, 0, Sha.HashSize);
            Array.Clear(destination, 0, Sha.HashSize);

            Sha.ComputeHash(source, new byte[] { 0, 1, 2, 3 }, destination);
            Sha.ComputeHash(source2, new byte[] { 0, 1, 2, 3 }, source2);

            Assert.Equal(source2, destination);
        }
    }
}
