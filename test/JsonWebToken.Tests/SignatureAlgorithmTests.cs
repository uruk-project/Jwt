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

        public override bool TryParse(string value, out SignatureAlgorithm algorithm)
        {
            return SignatureAlgorithm.TryParse(value, out algorithm);
        }

        protected override bool EqualsOperatorOverload(SignatureAlgorithm x, SignatureAlgorithm y)
            => x == y;

        protected override bool NotEqualsOperatorOverload(SignatureAlgorithm x, SignatureAlgorithm y)
            => x != y;


        [Fact]
        public override void TryParse_Fail()
        {
            base.TryParse_Fail();
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out SignatureAlgorithm algorithm)
        {
            return SignatureAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        [Fact]
        public override void TryParseSlow_Fail()
        {
            base.TryParseSlow_Fail();
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

        [Theory]
        [InlineData("HS256")]
        [InlineData("HS384")]
        [InlineData("HS512")]
        [InlineData("ES256")]
        [InlineData("ES256K")]
        [InlineData("ES384")]
        [InlineData("ES512")]
        [InlineData("RS256")]
        [InlineData("RS384")]
        [InlineData("RS512")]
        [InlineData("PS256")]
        [InlineData("PS384")]
        [InlineData("PS512")]
        [InlineData("none")]
        public override void AssertEquals(string algorithm)
        {
            SignatureAlgorithm.TryParse(algorithm, out var alg1);
            AssertEqualsCore(alg1, alg1);

            var alg2 = new SignatureAlgorithm(alg1.Id, algorithm, alg1.Category, alg1.RequiredKeySizeInBits, alg1.HashAlgorithm);
            AssertEqualsCore(alg1, alg2);
        }

        [Theory]
        [InlineData("HS256")]
        [InlineData("HS384")]
        [InlineData("HS512")]
        [InlineData("ES256")]
        [InlineData("ES256K")]
        [InlineData("ES384")]
        [InlineData("ES512")]
        [InlineData("RS256")]
        [InlineData("RS384")]
        [InlineData("RS512")]
        [InlineData("PS256")]
        [InlineData("PS384")]
        [InlineData("PS512")]
        [InlineData("none")]
        public override void AssertNotEquals(string algorithm)
        {
            SignatureAlgorithm.TryParse(algorithm, out var alg);
            foreach (var item in SignatureAlgorithm.SupportedAlgorithms)
            {
                if (item.Id != alg.Id)
                {
                    AssertNotEqualsCore(alg, item);
                }
            }
        }
    }
}