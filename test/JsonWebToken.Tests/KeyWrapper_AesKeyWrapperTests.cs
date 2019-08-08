using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class KeyWrapper_AesKeyWrapperTests : KeyWrapperTestsBase
    {
        private Jwk TryWrapKey_Success(SymmetricJwk keyToWrap, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var keyEncryptionKey = SymmetricJwk.GenerateKey(alg.RequiredKeySizeInBits);
            var wrapper = new AesKeyWrapper(keyEncryptionKey, enc, alg);
            var cek = WrapKey(wrapper, keyToWrap, out var header);

            Assert.Equal(0, header.Count);
            return cek;
        }

        [Theory]
        [MemberData(nameof(GetAesWrappingAlgorithms))]
        public void TryWrapKey_WithStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var contentEncryptionKey = SymmetricJwk.GenerateKey(enc.RequiredKeySizeInBits);
            Jwk cek = TryWrapKey_Success(contentEncryptionKey, enc, alg);
            Assert.Equal(contentEncryptionKey, cek);
        }

        public static IEnumerable<object[]> GetAesWrappingAlgorithms()
        {
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes256KW };
            yield return new object[] { EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes256KW };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes256KW };
            yield return new object[] { EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes256KW };
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
            Jwk cek = null;
            int bytesWritten = 0;
            Assert.Throws<ArgumentException>(() => wrapper.WrapKey(null, header, destination, out cek, out bytesWritten));

            Assert.Equal(0, bytesWritten);
            Assert.Equal(0, header.Count);
            Assert.Null(cek);
        }
    }
}
