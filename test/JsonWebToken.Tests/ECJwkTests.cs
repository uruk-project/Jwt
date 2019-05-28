using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace JsonWebToken.Tests
{
    public class ECJwkTests : JwkTestsBase
    {
        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override KeyWrapper CreateKeyWrapper_Succeed(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            return base.CreateKeyWrapper_Succeed(key, enc, alg);
        }

        [Theory]
        [MemberData(nameof(GetSignatureValidationKeys))]
        public override Signer CreateSignerForValidation_Succeed(Jwk key, SignatureAlgorithm alg)
        {
            return base.CreateSignerForValidation_Succeed(key, alg);
        }

        [Theory]
        [MemberData(nameof(GetSignatureCreationKeys))]
        public override Signer CreateSignerForSignature_Succeed(Jwk key, SignatureAlgorithm alg)
        {
            return base.CreateSignerForSignature_Succeed(key, alg);
        }

        [Fact]
        public override void Canonicalize()
        {
            var jwk = ECJwk.GenerateKey(EllipticalCurve.P256, true);
            var canonicalizedKey = (ECJwk)CanonicalizeKey(jwk);

            Assert.Null(canonicalizedKey.D);

            Assert.Equal(EllipticalCurve.P256.Id, canonicalizedKey.Crv.Id);
            Assert.NotEmpty(canonicalizedKey.X);
            Assert.NotEmpty(canonicalizedKey.Y);
        }

        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override void IsSupportedKeyWrapping_Success(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            Assert.True(key.IsSupported(alg));
        }

        [Theory]
        [MemberData(nameof(GetSignatureCreationKeys))]
        public override void IsSupportedSignature_Success(Jwk key, SignatureAlgorithm alg)
        {
            Assert.True(key.IsSupported(alg));
        }

        public static IEnumerable<object[]> GetWrappingKeys()
        {
            yield return new object[] { _privateEcc256Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW };
            yield return new object[] { _privateEcc256Key, EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.EcdhEsAes192KW };
            yield return new object[] { _privateEcc256Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEsAes256KW };
            yield return new object[] { _privateEcc256Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEs };

            yield return new object[] { _privateEcc384Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW };
            yield return new object[] { _privateEcc384Key, EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.EcdhEsAes192KW };
            yield return new object[] { _privateEcc384Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEsAes256KW };
            yield return new object[] { _privateEcc384Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEs };

            yield return new object[] { _privateEcc521Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW };
            yield return new object[] { _privateEcc521Key, EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.EcdhEsAes192KW };
            yield return new object[] { _privateEcc521Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEsAes256KW };
            yield return new object[] { _privateEcc521Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEs };
        }

        public static IEnumerable<object[]> GetSignatureValidationKeys()
        {
            yield return new object[] { _publicEcc256Key, SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { _publicEcc256Key, SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { _publicEcc256Key, SignatureAlgorithm.EcdsaSha512 };

            yield return new object[] { _publicEcc384Key, SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { _publicEcc384Key, SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { _publicEcc384Key, SignatureAlgorithm.EcdsaSha512 };

            yield return new object[] { _publicEcc521Key, SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { _publicEcc521Key, SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { _publicEcc521Key, SignatureAlgorithm.EcdsaSha512 };
        }

        public static IEnumerable<object[]> GetSignatureCreationKeys()
        {
            yield return new object[] { _privateEcc256Key, SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { _privateEcc256Key, SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { _privateEcc256Key, SignatureAlgorithm.EcdsaSha512 };

            yield return new object[] { _privateEcc384Key, SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { _privateEcc384Key, SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { _privateEcc384Key, SignatureAlgorithm.EcdsaSha512 };

            yield return new object[] { _privateEcc521Key, SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { _privateEcc521Key, SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { _privateEcc521Key, SignatureAlgorithm.EcdsaSha512 };
        }

        [Theory]
        [InlineData("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}")]
        [InlineData("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}")]
        [InlineData("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"object\":{\"property\":true},\"float\":123.456,\"integer\":1234,\"boolean\":true,\"string\":\"hello\",\"null\":null,\"array\":[\"string\", 1, true, false, null, {}, [0]]}")]
        [InlineData("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"object\":{\"property\":true},\"float\":123.456,\"integer\":1234,\"boolean\":true,\"string\":\"hello\",\"null\":null,\"array\":[\"string\", 1, true, false, null, {}, [0]]}")]
        public override void FromJson(string json)
        {
            // https://tools.ietf.org/html/rfc7517#appendix-A.1
            var key = Jwk.FromJson(json);
            Assert.NotNull(key);
            var jwk = Assert.IsType<ECJwk>(key);

            Assert.Equal("1", jwk.Kid);
            Assert.True(JwkUseNames.Enc.SequenceEqual(jwk.Use));

            Assert.Equal(Encoding.UTF8.GetBytes("P-256"), jwk.Crv.Name);
            Assert.Equal(jwk.X, Base64Url.Decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"));
            Assert.Equal(jwk.Y, Base64Url.Decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"));
        }

        [Theory]
        [InlineData("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"],\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\",\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\",\"key_ops\":[\"sign\"],\"x5u\":\"https://example.com\"}")]
        [InlineData("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"],\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\",\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\",\"key_ops\":[\"sign\"],\"x5u\":\"https://example.com\"}")]
        public override void FromJson_WithProperties(string json)
        {
            var key = Jwk.FromJson(json);
            Assert.NotNull(key);
            var jwk = Assert.IsType<ECJwk>(key);

            Assert.NotNull(jwk.X509CertificateChain);
            Assert.NotEmpty(jwk.X509CertificateChain);
            Assert.NotEmpty(jwk.X5c);

            Assert.Equal(Base64Url.Decode("dGhpcyBpcyBhIFNIQTEgdGVzdCE"), jwk.X5t);
            Assert.Equal(Base64Url.Decode("dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA"), jwk.X5tS256);
            Assert.Equal("sign", jwk.KeyOps[0]);
            Assert.Equal("https://example.com", jwk.X5u);
        }

        [Fact]
        public override void WriteTo()
        {
            var key = ECJwk.GenerateKey(EllipticalCurve.P256, true, SignatureAlgorithm.EcdsaSha256);
            key.Kid = "kid-ec";
            key.KeyOps.Add("sign");
            key.Use = JwkUseNames.Sig.ToArray();
            key.X5t = Base64Url.Decode("dGhpcyBpcyBhIFNIQTEgdGVzdCE");
            key.X5tS256 = Base64Url.Decode("dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA");
            key.X5u = "https://example.com";
            key.X5c.Add(Convert.FromBase64String("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="));

            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                key.Serialize(bufferWriter);
                var json = Encoding.UTF8.GetString(bufferWriter.WrittenSpan);

                Assert.Contains("\"kid\":\"kid-ec\"", json);
                Assert.Contains("\"key_ops\":[\"sign\"]", json);
                Assert.Contains("\"use\":\"sig\"", json);
                Assert.Contains("\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\"", json);
                Assert.Contains("\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\"", json);
                Assert.Contains("\"x5u\":\"https://example.com\"", json);
                Assert.Contains("\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"]".Replace("+", "\\u002b"), json);

                Assert.Contains("\"crv\":\"P-256\"", json);
                Assert.Contains("\"x\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.X)) + "\"", json);
                Assert.Contains("\"y\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.Y)) + "\"", json);
                Assert.Contains("\"d\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.D)) + "\"", json);
            }
        }

        private static readonly ECJwk _privateEcc256Key = new ECJwk
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        );

        private static readonly ECJwk _publicEcc256Key = new ECJwk
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        );

        private static readonly ECJwk _publicEcc384Key = new ECJwk
        (
            crv: EllipticalCurve.P384,
            d: "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            x: "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            y: "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        );

        private static readonly ECJwk _privateEcc384Key = new ECJwk
        (
            crv: EllipticalCurve.P384,
            d: "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            x: "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            y: "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        );

        private static readonly ECJwk _privateEcc521Key = new ECJwk
        (
            crv: EllipticalCurve.P521,
            d: "Adri8PbGJBWN5upp_67cKF8E0ADCF-w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HISTMh_RSmFFhTfBH",
            x: "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            y: "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        );

        private static readonly ECJwk _publicEcc521Key = new ECJwk
        (
            crv: EllipticalCurve.P521,
            x: "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            y: "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        );
    }
}
