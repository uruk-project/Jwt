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

        public override bool TryParse(string value, out CompressionAlgorithm algorithm)
        {
            return CompressionAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out CompressionAlgorithm algorithm)
        {
            return CompressionAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        protected override bool EqualsOperatorOverload(CompressionAlgorithm x, CompressionAlgorithm y)
            => x == y;
        protected override bool NotEqualsOperatorOverload(CompressionAlgorithm x, CompressionAlgorithm y)
            => x != y;

        [Theory]
        [ClassData(typeof(AlgorithmFixture<CompressionAlgorithm>))]
        public override void TryParse_Success(CompressionAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Fact]
        public override void TryParse_Fail()
        {
            base.TryParse_Fail();
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<CompressionAlgorithm>))]
        public override void TryParseSlow_Success(CompressionAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }

        [Fact]
        public override void TryParseSlow_Fail()
        {
            base.TryParseSlow_Fail();
        }

        [Theory]
        [InlineData("DEF")]
        public override void AssertEquals(string algorithm)
        {
            CompressionAlgorithm.TryParse(algorithm, out var alg1);
            AssertEqualsCore(alg1, alg1);

            var alg2 = new CompressionAlgorithm(alg1.Id, algorithm, alg1.Compressor, alg1.Decompressor, alg1.Enabled);
            AssertEqualsCore(alg1, alg2);
        }

        [Theory]
        [InlineData("DEF")]
        public override void AssertNotEquals(string algorithm)
        {
            CompressionAlgorithm.TryParse(algorithm, out var alg);
            foreach (var item in CompressionAlgorithm.SupportedAlgorithms)
            {
                if (item.Id != alg.Id)
                {
                    AssertNotEqualsCore(alg, item);
                }
            }
        }
    }
}