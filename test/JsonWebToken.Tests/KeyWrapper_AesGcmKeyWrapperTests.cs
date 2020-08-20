#if SUPPORT_AESGCM
using System;
using System.Collections.Generic;
using JsonWebToken.Internal;
using Xunit;

namespace JsonWebToken.Tests
{
    public class KeyWrapper_AesGcmKeyWrapperTests : KeyWrapperTestsBase
    {
        private Jwk TryWrapKey_Success(SymmetricJwk keyToWrap, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var keyEncryptionKey = SymmetricJwk.GenerateKey(alg.RequiredKeySizeInBits);
            var wrapper = new AesGcmKeyWrapper(keyEncryptionKey, enc, alg);
            var cek = WrapKey(wrapper, keyToWrap, out var header);

            Assert.Equal(2, header.Count);
            Assert.True(header.ContainsKey("iv"));
            Assert.True(header.ContainsKey("tag"));
            return cek;
        }

        public static IEnumerable<object[]> GetAesWrappingAlgorithms()
        {
            yield return new object[] { EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.Aes128GcmKW };
            yield return new object[] { EncryptionAlgorithm.Aes192Gcm, KeyManagementAlgorithm.Aes192GcmKW };
            yield return new object[] { EncryptionAlgorithm.Aes256Gcm, KeyManagementAlgorithm.Aes256GcmKW };
        }

        [Theory]
        [MemberData(nameof(GetAesWrappingAlgorithms))]
        public void TryWrapKey_WithStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var contentEncryptionKey = SymmetricJwk.GenerateKey(enc.RequiredKeySizeInBits);
            Jwk cek = TryWrapKey_Success(contentEncryptionKey, enc, alg);
            Assert.Equal(contentEncryptionKey, cek);
        }

        [Theory]
        [MemberData(nameof(GetAesWrappingAlgorithms))]
        public void TryWrapKey_WithoutStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            Jwk cek = TryWrapKey_Success(null, enc, alg);
            Assert.NotNull(cek);
        }

        [Fact]
        public void WrapKey_Failure()
        {
            var keyEncryptionKey = SymmetricJwk.GenerateKey(256);
            var contentEncryptionKey = SymmetricJwk.GenerateKey(256);
            var wrapper = new AesGcmKeyWrapper(keyEncryptionKey, EncryptionAlgorithm.Aes256Gcm, KeyManagementAlgorithm.Aes256GcmKW);
            var destination = new byte[0];
            var header = new JwtObject();
            Assert.Throws<ArgumentException>(() => wrapper.WrapKey(contentEncryptionKey, header, destination));

            Assert.Equal(0, header.Count);
        }
    }
}
#endif