using System;
using System.Collections.Generic;
using Xunit;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Tests
{
    public class KeyWrapper_DirectKeyWrapperTests : KeyWrapperTestsBase
    {
        private Jwk TryWrapKey_Success(SymmetricJwk keyToWrap, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var keyEncryptionKey = SymmetricJwk.GenerateKey(alg.RequiredKeySizeInBits);
            var wrapper = new DirectKeyWrapper(keyEncryptionKey, enc, alg);
            var cek = WrapKey(wrapper, keyToWrap, out var header);

            Assert.Equal(0, header.Count);
            Assert.True(keyEncryptionKey.K.SequenceEqual(((SymmetricJwk)cek).K));
            return cek;
        }

        [Theory]
        [MemberData(nameof(GetAesWrappingAlgorithms))]
        public void TryWrapKey_WithStaticKey_Throws(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var contentEncryptionKey = SymmetricJwk.GenerateKey(enc.RequiredKeySizeInBits);
            Assert.Throws<ArgumentException>(() => TryWrapKey_Success(contentEncryptionKey, enc, alg));
        }

        public static IEnumerable<object[]> GetAesWrappingAlgorithms()
        {
            yield return new object[] { EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.Dir };
            yield return new object[] { EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.Dir };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.Dir };
            yield return new object[] { EncryptionAlgorithm.A128Gcm, KeyManagementAlgorithm.Dir };
            yield return new object[] { EncryptionAlgorithm.A192Gcm, KeyManagementAlgorithm.Dir };
            yield return new object[] { EncryptionAlgorithm.A256Gcm, KeyManagementAlgorithm.Dir };
        }

        [Theory]
        [MemberData(nameof(GetAesWrappingAlgorithms))]
        public void TryWrapKey_WithoutStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            Jwk cek = TryWrapKey_Success(null, enc, alg);
            Assert.NotNull(cek);
        }
    }
}
