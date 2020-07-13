#if NETCOREAPP3_0 || NET47
using System.Collections.Generic;
using System.Text;
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using Xunit;

namespace JsonWebToken.Tests
{
    public class EcKeyWrapTests
    {
        private readonly ECJwk _aliceKey = new ECJwk
        (
            crv: EllipticalCurve.P256,
            d: "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
            x: "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            y: "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
        );
        private readonly ECJwk _bobKey = new ECJwk
        (
            crv: EllipticalCurve.P256,
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        );

        [Fact]
        public void Wrap_Rfc7518_Appendix_C()
        {
            var kwp = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.EcdhEs);
            var header = new JwtObject
            {
                new JwtProperty(HeaderParameters.ApuUtf8, Base64Url.Encode("Alice")),
                new JwtProperty(HeaderParameters.ApvUtf8, Base64Url.Encode("Bob"))
            };

            var cek = kwp.WrapKey(_aliceKey, header, null);

            var expected = new byte[] { 86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26 };
            Assert.Equal(expected, cek.AsSpan().ToArray());
        }

        [Fact]
        public void Unwrap()
        {
            var kwp = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize()];
            var header = new JwtObject
            {
                new JwtProperty(HeaderParameters.ApuUtf8, Base64Url.Encode("Alice")),
                new JwtProperty(HeaderParameters.ApvUtf8, Base64Url.Encode("Bob"))
            };

            kwp.WrapKey(_aliceKey, header, wrappedKey);

            var kuwp = new EcdhKeyUnwrapper(_bobKey, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW);
            var apu = Encoding.UTF8.GetString(Base64Url.Encode("Alice")); ;
            var apv = Encoding.UTF8.GetString(Base64Url.Encode("Bob"));
            var epk = ((JwtObject)header[HeaderParameters.EpkUtf8].Value).ToString();
            var jwtHeader = JwtHeader.FromJson($"{{\"apu\":\"{apu}\",\"apv\":\"{apv}\",\"epk\":{epk}}}");

            byte[] unwrappedKey = new byte[kuwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kuwp.TryUnwrapKey(wrappedKey, unwrappedKey, jwtHeader, out _);

            Assert.True(unwrapped);
        }

        [Fact]
        public void Unwrap2()
        {
            var kwp = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize()];
            var header = new JwtObject
            {
                new JwtProperty(HeaderParameters.ApuUtf8, Base64Url.Encode("Alice")),
                new JwtProperty(HeaderParameters.ApvUtf8, Base64Url.Encode("Bob"))
            };

            kwp.WrapKey(_aliceKey, header, wrappedKey);

            var kuwp = new EcdhKeyUnwrapper(_bobKey, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW);
            var apu = Encoding.UTF8.GetString(Base64Url.Encode("Alice")); ;
            var apv = Encoding.UTF8.GetString(Base64Url.Encode("Bob"));
            var epk = ((JwtObject)header[HeaderParameters.EpkUtf8].Value).ToString();
            var jwtHeader = JwtHeader.FromJson($"{{\"apu\":\"{apu}\",\"apv\":\"{apv}\",\"epk\":{epk}}}");

            byte[] unwrappedKey = new byte[kuwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kuwp.TryUnwrapKey(wrappedKey, unwrappedKey, jwtHeader, out int bytesWritten);

            Assert.True(unwrapped);
        }
    }
}
#endif