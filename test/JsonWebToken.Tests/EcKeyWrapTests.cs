﻿#if SUPPORT_ELLIPTIC_CURVE
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json.Linq;
using Xunit;
using JsonWebToken.Cryptography;
using System;
using System.Runtime.InteropServices;

namespace JsonWebToken.Tests
{
    public class EcKeyWrapTests
    {
        private readonly ECJwk _aliceKey = ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P256,
            d: "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
            x: "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            y: "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
        );
        private readonly ECJwk _bobKey = ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P256,
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        );

        [Fact]
        public void Wrap_Rfc7518_Appendix_C()
        {
            var kwp = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.A128Gcm, KeyManagementAlgorithm.EcdhEs);
            var header = new JwtHeader
            {
                { JwtHeaderParameterNames.Apu, Utf8.GetString(Base64Url.Encode("Alice")) },
                { JwtHeaderParameterNames.Apv, Utf8.GetString(Base64Url.Encode("Bob")) }
            };

            Span<byte> wrappedKey = stackalloc byte[kwp.GetKeyWrapSize()];
            var cek = kwp.WrapKey(_aliceKey, header, wrappedKey);

            var expected = new byte[] { 86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26 };
            Assert.Equal(expected, cek.AsSpan().ToArray());
        }

        [Fact]
        public void Unwrap()
        {
            var kwp = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.EcdhEsA128KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize()];
            var header = new JwtHeader
            {
                { JwtHeaderParameterNames.Apu, Utf8.GetString(Base64Url.Encode("Alice")) },
                { JwtHeaderParameterNames.Apv, Utf8.GetString(Base64Url.Encode("Bob")) }
            };

            kwp.WrapKey(_aliceKey, header, wrappedKey);

            var kuwp = new EcdhKeyUnwrapper(_bobKey, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.EcdhEsA128KW);
            var apu = Encoding.UTF8.GetString(Base64Url.Encode("Alice")); ;
            var apv = Encoding.UTF8.GetString(Base64Url.Encode("Bob"));
            header.TryGetValue(JwtHeaderParameterNames.Epk, out var epkElement);
            var epk = (Jwk)epkElement.Value;
            var parsed = JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes($"{{\"apu\":\"{apu}\",\"apv\":\"{apv}\",\"epk\":{epk}}}"), null, TokenValidationPolicy.NoValidation, out var jwtHeader, out var error);
            Assert.True(parsed);

            byte[] unwrappedKey = new byte[kuwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kuwp.TryUnwrapKey(wrappedKey, unwrappedKey, jwtHeader, out _);

            Assert.True(unwrapped);
        }

        [Fact]
        public void Unwrap2()
        {
            var kwp = new EcdhKeyWrapper(_bobKey, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.EcdhEsA128KW);
            byte[] wrappedKey = new byte[kwp.GetKeyWrapSize()];
            var header = new JwtHeader
            {
                { JwtHeaderParameterNames.Apu, Utf8.GetString(Base64Url.Encode("Alice")) },
                { JwtHeaderParameterNames.Apv, Utf8.GetString(Base64Url.Encode("Bob")) }
            };

            kwp.WrapKey(_aliceKey, header, wrappedKey);

            var kuwp = new EcdhKeyUnwrapper(_bobKey, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.EcdhEsA128KW);
            var apu = Encoding.UTF8.GetString(Base64Url.Encode("Alice")); ;
            var apv = Encoding.UTF8.GetString(Base64Url.Encode("Bob"));
            header.TryGetValue(JwtHeaderParameterNames.Epk, out var epkElement);
            var epk = (Jwk)epkElement.Value;
            var parsed = JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes($"{{\"apu\":\"{apu}\",\"apv\":\"{apv}\",\"epk\":{epk}}}"), null, TokenValidationPolicy.NoValidation, out var jwtHeader, out var error);
            Assert.True(parsed);

            byte[] unwrappedKey = new byte[kuwp.GetKeyUnwrapSize(wrappedKey.Length)];
            var unwrapped = kuwp.TryUnwrapKey(wrappedKey, unwrappedKey, jwtHeader, out int bytesWritten);

            Assert.True(unwrapped);
        }
    }
}
#endif
