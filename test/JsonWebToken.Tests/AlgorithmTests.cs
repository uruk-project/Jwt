using System;
using System.Text;
using System.Text.Json;
using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public abstract class AlgorithmTests<T> where T : class, IAlgorithm
    {
        public abstract bool TryParse(ReadOnlySpan<byte> value, out T algorithm);

        public virtual void TryParse_Success(T expected)
        {
            var parsed = TryParse(expected.Utf8Name, out var algorithm);
            Assert.True(parsed);
            Assert.NotNull(algorithm);
            Assert.Same(expected, algorithm);
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

        [Fact]
        public void TryParseEmpty_ThrowException()
        {
            var parsed = TryParse(ReadOnlySpan<byte>.Empty, out var algorithm);
            Assert.False(parsed);
            Assert.Null(algorithm);
        }
    }
}