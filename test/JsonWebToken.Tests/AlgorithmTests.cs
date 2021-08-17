using System;
using System.Text;
using System.Text.Json;
using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public abstract class AlgorithmTests<T> where T : class, IAlgorithm
    {
        public abstract bool TryParse(string value, out T algorithm);
        public abstract bool TryParse(ReadOnlySpan<byte> value, out T algorithm);

        public virtual void TryParse_Success(T expected)
        {
            var parsed = TryParse(expected.Utf8Name, out var algorithm);
            Assert.True(parsed);
            Assert.NotNull(algorithm);
            Assert.Same(expected, algorithm);
            parsed = TryParse(Utf8.GetString(expected.Utf8Name), out var algorithm2);
            Assert.True(parsed);
            Assert.NotNull(algorithm2);
            Assert.Same(expected, algorithm2);
        }

        public virtual void TryParse_Fail()
        {
            var parsed = TryParse(JsonEncodedText.Encode("FAKE").EncodedUtf8Bytes, out var algorithm);
            Assert.False(parsed);
            Assert.Null(algorithm);
            parsed = TryParse("FAKE", out var algorithm2);
            Assert.False(parsed);
            Assert.Null(algorithm2);
        }

        public abstract bool TryParseSlow(ref Utf8JsonReader reader, out T algorithm);

        public virtual void TryParseSlow_Success(T expected)
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes("\"" + expected.Name + "\""));
            reader.Read();
            var parsed = TryParseSlow(ref reader, out var algorithm);
            Assert.True(parsed);
            Assert.NotNull(algorithm);
            Assert.Same(expected, algorithm);
        }

        public virtual void TryParseSlow_Fail()
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes("\"FAKE\""));
            reader.Read();
            var parsed = TryParseSlow(ref reader, out var algorithm);
            Assert.False(parsed);
            Assert.Null(algorithm);
        }

        [Fact]
        public void TryParseEmpty_ThrowException()
        {
            var parsed = TryParse(ReadOnlySpan<byte>.Empty, out var algorithm);
            Assert.False(parsed);
            Assert.Null(algorithm);
        }

        public abstract void AssertEquals(string algorithm);

        protected void AssertEqualsCore(T algorithm1, T algorithm2)
        {
            Assert.True(EqualsOperatorOverload(algorithm1, algorithm2));
            Assert.False(NotEqualsOperatorOverload(algorithm1, algorithm2));
            if (algorithm1 is not null)
            {
                Assert.True(algorithm1.Equals(algorithm2));
                Assert.Equal(algorithm1.GetHashCode(), algorithm2.GetHashCode());
            }
        }

        protected abstract bool EqualsOperatorOverload(T x, T y);
        protected abstract bool NotEqualsOperatorOverload(T x, T y);

        public abstract void AssertNotEquals(string algorithm);

        protected void AssertNotEqualsCore(T algorithm1, T algorithm2)
        {
            Assert.False(EqualsOperatorOverload(algorithm1, algorithm2));
            Assert.True(NotEqualsOperatorOverload(algorithm1, algorithm2));
            if (algorithm1 is not null)
            {
                Assert.False(algorithm1.Equals(algorithm2));
                Assert.NotEqual(algorithm1.GetHashCode(), algorithm2.GetHashCode());
            }
        }
    }
}