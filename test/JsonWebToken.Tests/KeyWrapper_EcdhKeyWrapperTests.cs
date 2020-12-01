#if NETCOREAPP
using System;
using System.Collections.Generic;
using Xunit;
using JsonWebToken.Cryptography;

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
            //foreach (var enc in new[] {
            //    EncryptionAlgorithm.Aes128CbcHmacSha256,
            //    EncryptionAlgorithm.Aes192CbcHmacSha384,
            //    EncryptionAlgorithm.Aes256CbcHmacSha512
            //})
            //{
            //    yield return new object[] { enc, KeyManagementAlgorithm.EcdhEs };
            //    yield return new object[] { enc, KeyManagementAlgorithm.EcdhEsAes128KW };
            //    yield return new object[] { enc, KeyManagementAlgorithm.EcdhEsAes192KW };
            //    yield return new object[] { enc, KeyManagementAlgorithm.EcdhEsAes256KW };
            //}

            yield return new object[] { EncryptionAlgorithm.A128Gcm, KeyManagementAlgorithm.EcdhEsA128KW };
            yield return new object[] { EncryptionAlgorithm.A192Gcm, KeyManagementAlgorithm.EcdhEsA192KW };
            yield return new object[] { EncryptionAlgorithm.A256Gcm, KeyManagementAlgorithm.EcdhEsA256KW };
        }

        [Theory]
        [MemberData(nameof(GetEcdhWrappingAlgorithms))]
        public void TryWrapKey_WithoutStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            Jwk cek = TryWrapKey_Success(null, enc, alg);
            Assert.NotNull(cek);
        }

        [Fact]
        public void WrapKey_Failure()
        {
            var keyEncryptionKey = ECJwk.GeneratePrivateKey(EllipticalCurve.P256);
            var wrapper = new EcdhKeyWrapper(keyEncryptionKey, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.EcdhEs);
            var destination = new byte[0];
            var header = new JwtHeader();
            Jwk cek = null;
            Assert.Throws<ArgumentNullException>(() => wrapper.WrapKey(null, null, destination));
            wrapper.Dispose();

            Assert.Equal(0, header.Count);
            Assert.Null(cek);
        }
    }
}
#endif