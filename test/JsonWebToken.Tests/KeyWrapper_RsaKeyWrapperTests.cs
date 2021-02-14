﻿using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;
using JsonWebToken.Cryptography;
using System.Runtime.InteropServices;

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
            var algorithms = new List<EncryptionAlgorithm>   
            {
                EncryptionAlgorithm.A128CbcHS256,
                EncryptionAlgorithm.A192CbcHS384,
                EncryptionAlgorithm.A256CbcHS512
            };
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                algorithms.Add(EncryptionAlgorithm.A128Gcm);
                algorithms.Add(EncryptionAlgorithm.A192Gcm);
                algorithms.Add(EncryptionAlgorithm.A256Gcm);
            }

            foreach (var enc in algorithms)
            {
                yield return new object[] { enc, KeyManagementAlgorithm.Rsa1_5 };
                yield return new object[] { enc, KeyManagementAlgorithm.RsaOaep };
#if !NETFRAMEWORK
                yield return new object[] { enc, KeyManagementAlgorithm.RsaOaep256 };
                yield return new object[] { enc, KeyManagementAlgorithm.RsaOaep384 };
                yield return new object[] { enc, KeyManagementAlgorithm.RsaOaep512 };
#endif
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
            var keyEncryptionKey = RsaJwk.GeneratePrivateKey(2048);
            var wrapper = new RsaKeyWrapper(keyEncryptionKey, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.RsaOaep);
            var destination = new byte[0];
            var header = new JwtHeader();

            Assert.Throws<CryptographicException>(() => wrapper.WrapKey(null, header, destination));
            wrapper.Dispose();
            Assert.Throws<ObjectDisposedException>(() => wrapper.WrapKey(null, header, destination));

            Assert.Equal(0, header.Count);
        }
    }
}
