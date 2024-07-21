#if !NET461
using System;
using System.Collections.Generic;
using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class KeyWrapper_EcdhKeyWrapperTests : KeyWrapperTestsBase
    {
        private Jwk TryWrapKey_Success(ECJwk keyToWrap, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var keyEncryptionKey = ECJwk.GeneratePrivateKey(EllipticalCurve.P256);
            var wrapper = new EcdhKeyWrapper(keyEncryptionKey, enc, alg);
            var cek = WrapKey(wrapper, keyToWrap, out var header);

            Assert.Equal(1, header.Count);
            Assert.True(header.ContainsKey(JwtHeaderParameterNames.Epk));

            return cek;
        }

        [Theory]
        [MemberData(nameof(GetEcdhWrappingAlgorithms))]
        public void TryWrapKey_WithStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var contentEncryptionKey = ECJwk.GeneratePrivateKey(EllipticalCurve.P256);
            Jwk cek = TryWrapKey_Success(contentEncryptionKey, enc, alg);
            Assert.NotNull(cek);
            Assert.IsType<SymmetricJwk>(cek);
        }

        public static IEnumerable<object[]> GetEcdhWrappingAlgorithms()
        {
            yield return new object[] { EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.EcdhEsA128KW };
            yield return new object[] { EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.EcdhEsA192KW };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.EcdhEsA256KW };
        }

        [Theory]
        [MemberData(nameof(GetEcdhWrappingAlgorithms))]
        public void TryWrapKey_WithoutStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            Jwk cek = TryWrapKey_Success(null, enc, alg);
            Assert.NotNull(cek);
        }
    }
}
#endif