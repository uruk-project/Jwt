using System;
using System.Buffers;
using System.Security.Cryptography;
using Xunit;
using CryptographicOperations = JsonWebToken.Cryptography.CryptographicOperations;

namespace JsonWebToken.Tests
{
    public static class FixedTimeEqualsTests
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(15)]
        [InlineData(16)]
        [InlineData(17)]
        [InlineData(31)]
        [InlineData(32)]
        [InlineData(33)]
        [InlineData(63)]
        [InlineData(64)]
        [InlineData(65)]
        [InlineData(96)]
        [InlineData(128)]
        [InlineData(256)]
        [InlineData(1024)]  
        [InlineData(1025)]
        public static void EqualReturnsTrue(int byteLength)
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan = new Span<byte>(rented, 0, byteLength);
            Fill(rented, 0, byteLength);

            byte[] rented2 = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan2 = new Span<byte>(rented2, 0, byteLength);

            testSpan.CopyTo(testSpan2);

            bool isEqual = CryptographicOperations.FixedTimeEquals(testSpan, testSpan2);

            ArrayPool<byte>.Shared.Return(rented);
            ArrayPool<byte>.Shared.Return(rented2);

            Assert.True(isEqual);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(15)]
        [InlineData(16)]
        [InlineData(17)]
        [InlineData(31)]
        [InlineData(32)]
        [InlineData(33)]
        [InlineData(63)]
        [InlineData(64)]
        [InlineData(65)]
        [InlineData(96)]
        [InlineData(128)]
        [InlineData(256)]
        [InlineData(1024)]
        [InlineData(1025)]
        public static void UnequalReturnsFalse(int byteLength)
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan = new Span<byte>(rented, 0, byteLength);
            Fill(rented, 0, byteLength);

            byte[] rented2 = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan2 = new Span<byte>(rented2, 0, byteLength);

            testSpan.CopyTo(testSpan2);
            testSpan[testSpan[0] % testSpan.Length] ^= 0xFF;

            bool isEqual = CryptographicOperations.FixedTimeEquals(testSpan, testSpan2);

            ArrayPool<byte>.Shared.Return(rented);
            ArrayPool<byte>.Shared.Return(rented2);

            Assert.False(isEqual);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(96)]
        [InlineData(128)]
        [InlineData(256)]
        [InlineData(512)]
        [InlineData(1024)]
        public static void DifferentLengthsReturnFalse(int byteLength)
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan = new Span<byte>(rented, 0, byteLength);
            Fill(rented, 0, byteLength);

            byte[] rented2 = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan2 = new Span<byte>(rented2, 0, byteLength);

            testSpan.CopyTo(testSpan2);

            bool isEqualA = CryptographicOperations.FixedTimeEquals(testSpan, testSpan2.Slice(0, byteLength - 1));
            bool isEqualB = CryptographicOperations.FixedTimeEquals(testSpan.Slice(0, byteLength - 1), testSpan2);

            ArrayPool<byte>.Shared.Return(rented);
            ArrayPool<byte>.Shared.Return(rented2);

            Assert.False(isEqualA, "value, value missing last byte");
            Assert.False(isEqualB, "value missing last byte, value");
        }

        [Fact]
        public static void EmptyReturnTrue()
        {
            int byteLength = 0;
            byte[] rented = ArrayPool<byte>.Shared.Rent(byteLength);
            Span<byte> testSpan = new Span<byte>(rented, 0, byteLength);
            Fill(rented, 0, byteLength);

            ReadOnlySpan<byte> emptySpan = ReadOnlySpan<byte>.Empty;

            bool isEqualA = CryptographicOperations.FixedTimeEquals(testSpan, emptySpan);
            bool isEqualB = CryptographicOperations.FixedTimeEquals(emptySpan, testSpan);

            ArrayPool<byte>.Shared.Return(rented);

            Assert.True(isEqualA, "FixedTimeEquals(testSpan, emptySpan)");
            Assert.True(isEqualB, "FixedTimeEquals(emptySpan, testSpan)");
        }

        private static void Fill(byte[] data, int offset, int count)
        {
            using var rnd = RandomNumberGenerator.Create();
            rnd.GetBytes(data, offset, count);
        }
    }
}