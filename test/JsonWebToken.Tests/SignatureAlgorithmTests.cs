using System;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class SignatureAlgorithmTests : AlgorithmTests<SignatureAlgorithm>
    {
        public override bool TryParse(ReadOnlySpan<byte> value, out SignatureAlgorithm algorithm)
        {
            return SignatureAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out SignatureAlgorithm algorithm)
        {
            return SignatureAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<SignatureAlgorithm>))]
        public override void TryParse_Success(SignatureAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<SignatureAlgorithm>))]
        public override void TryParseSlow_Success(SignatureAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }
    }
}