using System;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class EncryptionAlgorithmTests : AlgorithmTests<EncryptionAlgorithm>
    {
        public override bool TryParse(ReadOnlySpan<byte> value, out EncryptionAlgorithm algorithm)
        {
            return EncryptionAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out EncryptionAlgorithm algorithm)
        {
            return EncryptionAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<EncryptionAlgorithm>))]
        public override void TryParse_Success(EncryptionAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<EncryptionAlgorithm>))]
        public override void TryParseSlow_Success(EncryptionAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }
    }
}