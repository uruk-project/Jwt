﻿using System;
using System.Collections.Generic;
using Xunit;
using JsonWebToken.Cryptography;

namespace JsonWebToken.Tests
{
    public class KeyWrapper_AesKeyWrapperTests : KeyWrapperTestsBase
    {
        private Jwk TryWrapKey_Success(SymmetricJwk keyToWrap, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var keyEncryptionKey = SymmetricJwk.GenerateKey(alg.RequiredKeySizeInBits);
            var wrapper = new AesKeyWrapper(keyEncryptionKey.K, enc, alg);
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
            yield return new object[] { EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.A128KW };
            yield return new object[] { EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.A128KW };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.A128KW };
            yield return new object[] { EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.A192KW };
            yield return new object[] { EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.A192KW };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.A192KW };
            yield return new object[] { EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.A256KW };
            yield return new object[] { EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.A256KW };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.A256KW };
            yield return new object[] { EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.A256KW };
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
            var wrapper = new AesKeyWrapper(keyEncryptionKey.K, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.A128KW);
            var destination = new byte[0];
            var header = new JwtHeader();
            Assert.Throws<ArgumentException>(() => wrapper.WrapKey(null, header, destination));

            Assert.Equal(0, header.Count);
        }
    }
}
