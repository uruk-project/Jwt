using System;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class KeyManagementAlgorithmTests : AlgorithmTests<KeyManagementAlgorithm>
    {
        public override bool TryParse(ReadOnlySpan<byte> value, out KeyManagementAlgorithm algorithm)
        {
            return KeyManagementAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out KeyManagementAlgorithm algorithm)
        {
            return KeyManagementAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<KeyManagementAlgorithm>))]
        public override void TryParse_Success(KeyManagementAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<KeyManagementAlgorithm>))]
        public override void TryParseSlow_Success(KeyManagementAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }
    }
}