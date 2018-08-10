using Xunit;
using System;
using Newtonsoft.Json.Linq;
using System.Text;

namespace JsonWebToken.Tests
{
    public class EcKeyWrapTests
    {
        private readonly EccJwk _aliceKey = new EccJwk
        {
            Kty = "EC",
            Crv = "P-256",
            X = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            Y = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            D = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
        };
        private readonly EccJwk _bobKey = new EccJwk
        {
            Kty = "EC",
            Crv = "P-256",
            X = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            Y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            D = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        };

        [Fact]
        public void Wrap()
        {
            var kwp = new EcdhKeyWrapProvider(_bobKey, ContentEncryptionAlgorithms.Aes128Gcm, KeyManagementAlgorithms.EcdhEs);
            byte[] wrappedKey = null;
            var header = new JObject
            {
                { HeaderParameters.Apu, Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Alice")) },
                { HeaderParameters.Apv, Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Bob")) }
            };

            var wrapped = kwp.TryWrapKey(_aliceKey, header, wrappedKey, out var cek, out var bytesWritten);
            Assert.True(wrapped);

            var expected = new byte[] { 86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26 };
            Assert.Equal(expected, cek.ToByteArray());
        }

        [Fact]
        public void Unwrap()
        {
            var kwp = new EcdhKeyWrapProvider(_bobKey, ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.EcdhEsAes128KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize()];
            var header = new JObject
            {
                { HeaderParameters.Apu, Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Alice")) },
                { HeaderParameters.Apv, Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Bob")) }
            };

            var wrapped = kwp.TryWrapKey(_aliceKey, header, wrappedKey, out var cek, out var bytesWritten);

            var kwp2 = new EcdhKeyWrapProvider(_bobKey, ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.EcdhEsAes128KW);
            var jwtHeader = new JwtHeader
            {
                Apu = Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Alice")),
                Apv = Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Bob")),
                Epk = header[HeaderParameters.Epk].ToObject<EccJwk>()
            };

            byte[] unwrappedKey = new byte[kwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kwp2.TryUnwrapKey(wrappedKey, unwrappedKey, jwtHeader, out bytesWritten);

            Assert.True(unwrapped);
        }

        [Fact]
        public void Unwrap2()
        {
            var kwp = new EcdhKeyWrapProvider(_bobKey, ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.EcdhEsAes128KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize()];
            var header = new JObject
            {
                { HeaderParameters.Apu, Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Alice")) },
                { HeaderParameters.Apv, Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Bob")) }
            };

            var wrapped = kwp.TryWrapKey(_aliceKey, header, wrappedKey, out var cek, out var bytesWritten);

            var kwp2 = new EcdhKeyWrapProvider(_bobKey, ContentEncryptionAlgorithms.Aes128CbcHmacSha256, KeyManagementAlgorithms.EcdhEsAes128KW);
            var jwtHeader = new JwtHeader
            {
                Apu = Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Alice")),
                Apv = Base64Url.Base64UrlEncode(Encoding.UTF8.GetBytes("Bob")),
                Epk = header[HeaderParameters.Epk].ToObject<EccJwk>()
            };

            byte[] unwrappedKey = new byte[kwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kwp2.TryUnwrapKey(wrappedKey, unwrappedKey, jwtHeader, out bytesWritten);

            Assert.True(unwrapped);
        }
    }
}
