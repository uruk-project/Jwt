using JsonWebToken.Internal;
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class KeyWrapper_RsaKeyWrapperTests : KeyWrapperTestsBase
    {
        private Jwk TryWrapKey_Success(SymmetricJwk keyToWrap, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var keyEncryptionKey = RsaJwk.GeneratePrivateKey(alg.RequiredKeySizeInBits);
            var wrapper = new RsaKeyWrapper(keyEncryptionKey, enc, alg);
            var cek = TryWrapKey(wrapper, keyToWrap, out var header);

            Assert.Equal(0, header.Count);
            return cek;
        }

        [Theory]
        [MemberData(nameof(GetRsaWrappingAlgorithms))]
        public void TryWrapKey_WithStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var contentEncryptionKey = SymmetricJwk.GenerateKey(enc.RequiredKeySizeInBytes * 8);
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
