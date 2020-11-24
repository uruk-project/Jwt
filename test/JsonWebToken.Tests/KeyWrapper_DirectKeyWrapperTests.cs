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
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Direct };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Direct };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Direct };
            yield return new object[] { EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.Direct };
            yield return new object[] { EncryptionAlgorithm.Aes192Gcm, KeyManagementAlgorithm.Direct };
            yield return new object[] { EncryptionAlgorithm.Aes256Gcm, KeyManagementAlgorithm.Direct };
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
