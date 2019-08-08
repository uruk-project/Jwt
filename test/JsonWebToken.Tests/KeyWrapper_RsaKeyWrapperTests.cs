using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class KeyWrapper_RsaKeyWrapperTests : KeyWrapperTestsBase
    {
        private Jwk TryWrapKey_Success(SymmetricJwk keyToWrap, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var keyEncryptionKey = RsaJwk.GeneratePrivateKey(alg.RequiredKeySizeInBits);
            var wrapper = new RsaKeyWrapper(keyEncryptionKey, enc, alg);
            var cek = WrapKey(wrapper, keyToWrap, out var header);

            Assert.Equal(0, header.Count);
            return cek;
        }

        [Theory]
        [MemberData(nameof(GetRsaWrappingAlgorithms))]
        public void TryWrapKey_WithStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var contentEncryptionKey = SymmetricJwk.GenerateKey(enc.RequiredKeySizeInBits);
            Jwk cek = TryWrapKey_Success(contentEncryptionKey, enc, alg);
            Assert.Equal(contentEncryptionKey, cek);
        }

        public static IEnumerable<object[]> GetRsaWrappingAlgorithms()
        {
            foreach (var enc in new[] {
                EncryptionAlgorithm.Aes128CbcHmacSha256,
                EncryptionAlgorithm.Aes192CbcHmacSha384,
                EncryptionAlgorithm.Aes256CbcHmacSha512,
                EncryptionAlgorithm.Aes128Gcm,
                EncryptionAlgorithm.Aes192Gcm,
                EncryptionAlgorithm.Aes256Gcm
            })
            {
                yield return new object[] { enc, KeyManagementAlgorithm.RsaOaep };
                yield return new object[] { enc, KeyManagementAlgorithm.RsaOaep256 };
                yield return new object[] { enc, KeyManagementAlgorithm.RsaOaep384 };
                yield return new object[] { enc, KeyManagementAlgorithm.RsaOaep512 };
                yield return new object[] { enc, KeyManagementAlgorithm.RsaPkcs1 };
            }
        }

        [Theory]
        [MemberData(nameof(GetRsaWrappingAlgorithms))]
        public void TryWrapKey_WithoutStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            Jwk cek = TryWrapKey_Success(null, enc, alg);
            Assert.NotNull(cek);
        }

        [Fact]
        public void WrapKey_Failure()
        {
            var keyEncryptionKey = RsaJwk.GenerateKey(2048, true);
            var wrapper = new RsaKeyWrapper(keyEncryptionKey, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.RsaOaep);
            var destination = new byte[0];
            var header = new JwtObject();

            int bytesWritten = 0;
            Jwk cek = null;
            Assert.Throws<CryptographicException>(() => wrapper.WrapKey(null, header, destination, out cek, out bytesWritten));
            wrapper.Dispose();
            Assert.Throws<ObjectDisposedException>(() => wrapper.WrapKey(null, header, destination, out cek, out bytesWritten));

            Assert.Equal(0, bytesWritten);
            Assert.Equal(0, header.Count);
            Assert.Null(cek);
        }
    }
}
