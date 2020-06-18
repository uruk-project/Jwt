using System;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class CompressionAlgorithmTests : AlgorithmTests<CompressionAlgorithm>
    {
        public override bool TryParse(ReadOnlySpan<byte> value, out CompressionAlgorithm algorithm)
        {
            return CompressionAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out CompressionAlgorithm algorithm)
        {
            return CompressionAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<CompressionAlgorithm>))]
        public override void TryParse_Success(CompressionAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<CompressionAlgorithm>))]
        public override void TryParseSlow_Success(CompressionAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }
    }
}