using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class KeyWrapper_DirectKeyWrapperTests : KeyWrapperTestsBase
    {
        private Jwk TryWrapKey_Success(SymmetricJwk keyToWrap, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var keyEncryptionKey = SymmetricJwk.GenerateKey(alg.RequiredKeySizeInBits);
            var wrapper = new DirectKeyWrapper(keyEncryptionKey, enc, alg);
            var cek = TryWrapKey(wrapper, keyToWrap, out var header);

            Assert.Equal(0, header.Count);
            Assert.Equal(keyEncryptionKey, cek);
            return cek;
        }

        [Theory]
        [MemberData(nameof(GetAesWrappingAlgorithms))]
        public void TryWrapKey_WithStaticKey_Throws(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var contentEncryptionKey = SymmetricJwk.GenerateKey(enc.RequiredKeySizeInBytes * 8);
            Assert.Throws<NotSupportedException>(() => TryWrapKey_Success(contentEncryptionKey, enc, alg));
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

        [Fact]
        public void WrapKey_Failure()
        {
            var keyEncryptionKey = SymmetricJwk.GenerateKey(128);
            var wrapper = new AesKeyWrapper(keyEncryptionKey, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes128KW);
            var destination = new byte[0];
            var header = new JwtObject();
            bool wrapped = wrapper.TryWrapKey(null, header, destination, out var cek, out int bytesWritten);

            Assert.False(wrapped);
            Assert.Equal(0, bytesWritten);
            Assert.Equal(0, header.Count);
            Assert.Null(cek);
        }
    }
}
