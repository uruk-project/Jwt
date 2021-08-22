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

        public override bool TryParse(string value, out KeyManagementAlgorithm algorithm)
        {
            return KeyManagementAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out KeyManagementAlgorithm algorithm)
        {
            return KeyManagementAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        protected override bool EqualsOperatorOverload(KeyManagementAlgorithm x, KeyManagementAlgorithm y)
            => x == y;
        protected override bool NotEqualsOperatorOverload(KeyManagementAlgorithm x, KeyManagementAlgorithm y)
            => x != y;

        [Theory]
        [ClassData(typeof(AlgorithmFixture<KeyManagementAlgorithm>))]
        public override void TryParse_Success(KeyManagementAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Fact]
        public override void TryParse_Fail()
        {
            base.TryParse_Fail();
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<KeyManagementAlgorithm>))]
        public override void TryParseSlow_Success(KeyManagementAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }

        [Fact]
        public override void TryParseSlow_Fail()
        {
            base.TryParseSlow_Fail();
        }

        [Theory]
        [InlineData("dir")]
        [InlineData("A128KW")]
        [InlineData("A192KW")]
        [InlineData("A256KW")]
        [InlineData("A128GCMKW")]
        [InlineData("A192GCMKW")]
        [InlineData("A256GCMKW")]
        [InlineData("RSA1_5")]
        [InlineData("RSA-OAEP")]
        [InlineData("RSA-OAEP-256")]
        [InlineData("RSA-OAEP-384")]
        [InlineData("RSA-OAEP-512")]
        [InlineData("ECDH-ES")]
        [InlineData("ECDH-ES+A128KW")]
        [InlineData("ECDH-ES+A192KW")]
        [InlineData("ECDH-ES+A256KW")]
        [InlineData("PBES2-HS256+A128KW")]
        [InlineData("PBES2-HS384+A192KW")]
        [InlineData("PBES2-HS512+A256KW")]
        public override void AssertEquals(string algorithm)
        {
            KeyManagementAlgorithm.TryParse(algorithm, out var alg1);
            AssertEqualsCore(alg1, alg1);

            var alg2 = new KeyManagementAlgorithm(alg1.Id, algorithm, alg1.Category, alg1.ProduceEncryptionKey);
            AssertEqualsCore(alg1, alg2);
        }

        [Theory]
        [InlineData("dir")]
        [InlineData("A128KW")]
        [InlineData("A192KW")]
        [InlineData("A256KW")]
        [InlineData("A128GCMKW")]
        [InlineData("A192GCMKW")]
        [InlineData("A256GCMKW")]
        [InlineData("RSA1_5")]
        [InlineData("RSA-OAEP")]
        [InlineData("RSA-OAEP-256")]
        [InlineData("RSA-OAEP-384")]
        [InlineData("RSA-OAEP-512")]
        [InlineData("ECDH-ES")]
        [InlineData("ECDH-ES+A128KW")]
        [InlineData("ECDH-ES+A192KW")]
        [InlineData("ECDH-ES+A256KW")]
        [InlineData("PBES2-HS256+A128KW")]
        [InlineData("PBES2-HS384+A192KW")]
        [InlineData("PBES2-HS512+A256KW")]
        public override void AssertNotEquals(string algorithm)
        {
            KeyManagementAlgorithm.TryParse(algorithm, out var alg);
            foreach (var item in KeyManagementAlgorithm.SupportedAlgorithms)
            {
                if (item.Id != alg.Id)
                {
                    AssertNotEqualsCore(alg, item);
                }
            }
        }
    }
}