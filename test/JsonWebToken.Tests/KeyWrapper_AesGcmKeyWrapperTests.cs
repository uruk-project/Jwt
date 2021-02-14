#if SUPPORT_AESGCM
using System;
using System.Collections.Generic;
using Xunit;
using JsonWebToken.Cryptography;
using System.Runtime.InteropServices;

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
            Assert.True(header.ContainsKey(JwtHeaderParameterNames.IV));
            Assert.True(header.ContainsKey(JwtHeaderParameterNames.Tag));
            return cek;
        }

        public static IEnumerable<object[]> GetAesWrappingAlgorithms()
        {
            yield return new object[] { EncryptionAlgorithm.A128Gcm, KeyManagementAlgorithm.A128GcmKW };
            yield return new object[] { EncryptionAlgorithm.A192Gcm, KeyManagementAlgorithm.A192GcmKW };
            yield return new object[] { EncryptionAlgorithm.A256Gcm, KeyManagementAlgorithm.A256GcmKW };
        }

        [Theory]
        [MemberData(nameof(GetAesWrappingAlgorithms))]
        public void TryWrapKey_WithStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return;
            }

            var contentEncryptionKey = SymmetricJwk.GenerateKey(enc.RequiredKeySizeInBits);
            Jwk cek = TryWrapKey_Success(contentEncryptionKey, enc, alg);
            Assert.Equal(contentEncryptionKey, cek);
        }

        [Theory]
        [MemberData(nameof(GetAesWrappingAlgorithms))]
        public void TryWrapKey_WithoutStaticKey_Success(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return;
            }

            Jwk cek = TryWrapKey_Success(null, enc, alg);
            Assert.NotNull(cek);
        }

        [Fact]
        public void WrapKey_Failure()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return;
            }

            var keyEncryptionKey = SymmetricJwk.GenerateKey(256);
            var contentEncryptionKey = SymmetricJwk.GenerateKey(256);
            var wrapper = new AesGcmKeyWrapper(keyEncryptionKey, EncryptionAlgorithm.A256Gcm, KeyManagementAlgorithm.A256GcmKW);
            var destination = Array.Empty<byte>();
            var header = new JwtHeader();
            Assert.Throws<ArgumentException>(() => wrapper.WrapKey(contentEncryptionKey, header, destination));

            Assert.Equal(0, header.Count);
        }
    }
}
#endif