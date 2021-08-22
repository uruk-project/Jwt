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

        public override bool TryParse(string value, out EncryptionAlgorithm algorithm)
        {
            return EncryptionAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out EncryptionAlgorithm algorithm)
        {
            return EncryptionAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        protected override bool EqualsOperatorOverload(EncryptionAlgorithm x, EncryptionAlgorithm y)
            => x == y;

        protected override bool NotEqualsOperatorOverload(EncryptionAlgorithm x, EncryptionAlgorithm y)
            => x != y;


        [Theory]
        [ClassData(typeof(AlgorithmFixture<EncryptionAlgorithm>))]
        public override void TryParse_Success(EncryptionAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Fact]
        public override void TryParse_Fail()
        {
            base.TryParse_Fail();
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<EncryptionAlgorithm>))]
        public override void TryParseSlow_Success(EncryptionAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }

        [Fact]
        public override void TryParseSlow_Fail()
        {
            base.TryParseSlow_Fail();
        }

        [Theory]
        [InlineData("A128CBC-HS256")]
        [InlineData("A192CBC-HS384")]
        [InlineData("A256CBC-HS512")]
        [InlineData("A128GCM")]
        [InlineData("A192GCM")]
        [InlineData("A256GCM")]
        public override void AssertEquals(string algorithm)
        {
            EncryptionAlgorithm.TryParse(algorithm, out var alg1);
            AssertEqualsCore(alg1, alg1);

            var alg2 = new EncryptionAlgorithm(alg1.Id, algorithm, alg1.RequiredKeySizeInBytes, alg1.SignatureAlgorithm, alg1.KeyWrappedSizeInBytes, alg1.Category);
            AssertEqualsCore(alg1, alg2);
        }

        [Theory]
        [InlineData("A128CBC-HS256")]
        [InlineData("A192CBC-HS384")]
        [InlineData("A256CBC-HS512")]
        [InlineData("A128GCM")]
        [InlineData("A192GCM")]
        [InlineData("A256GCM")]
        public override void AssertNotEquals(string algorithm)
        {
            EncryptionAlgorithm.TryParse(algorithm, out var alg);
            foreach (var item in EncryptionAlgorithm.SupportedAlgorithms)
            {
                if (item.Id != alg.Id)
                {
                    AssertNotEqualsCore(alg, item);
                }
            }
        }
    }
}