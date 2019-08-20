using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;
using Xunit.Abstractions;

namespace JsonWebToken.Tests
{
    public class KeyWrapper_RsaKeyWrapperTests : KeyWrapperTestsBase
    {
        private readonly ITestOutputHelper output;

        public KeyWrapper_RsaKeyWrapperTests(ITestOutputHelper output)
        {
            this.output = output;
        }

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

            Assert.Throws<CryptographicException>(() => wrapper.WrapKey(null, header, destination));
            wrapper.Dispose();
            Assert.Throws<ObjectDisposedException>(() => wrapper.WrapKey(null, header, destination));

            Assert.Equal(0, header.Count);
        }

        [Theory]
        [MemberData(nameof(RsaPadding))]
        public void Rsa_TryEncrypt_DestinationTooSmall(RSAEncryptionPadding padding)
        {
            var data = new byte[1024];
            RandomNumberGenerator.Fill(data);
            var destination = new byte[0];
            var legalKeySizes = RSA.Create(4096).LegalKeySizes;
            output.WriteLine("RSA legal key sizes:");
            for (int i = 0; i < legalKeySizes.Length; i++)
            {
                output.WriteLine(legalKeySizes[i].MinSize + "/" + legalKeySizes[i].MaxSize + "/" + legalKeySizes[i].SkipSize);
            }

            using (var rsa = RSA.Create(512))
            {
                var result = rsa.TryEncrypt(data, destination, padding, out int bytesWritten);

                Assert.False(result);
            }
        }

        public static IEnumerable<object[]> RsaPadding()
        {
            yield return new object[] { RSAEncryptionPadding.OaepSHA1 };
            yield return new object[] { RSAEncryptionPadding.OaepSHA256 };
            yield return new object[] { RSAEncryptionPadding.OaepSHA384 };
            yield return new object[] { RSAEncryptionPadding.OaepSHA512 };
            yield return new object[] { RSAEncryptionPadding.Pkcs1 };
        }
    }
}
