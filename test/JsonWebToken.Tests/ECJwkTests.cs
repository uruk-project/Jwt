#if !NET461
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JsonWebToken.Cryptography;
using JsonWebToken.Internal;
using JsonWebToken.Tests.Cryptography;
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
        [MemberData(nameof(GetValidSignatureKeys))]
        public override Signer CreateSigner_Succeed(Jwk key, SignatureAlgorithm alg)
        {
            return base.CreateSigner_Succeed(key, alg);
        }

        [Theory]
        [MemberData(nameof(GetInvalidKeys))]
        public override Signer CreateSigner_Failed(Jwk key, SignatureAlgorithm alg)
        {
            return base.CreateSigner_Failed(key, alg);
        }

        [Fact]
        public override void Canonicalize()
        {
            var jwk = ECJwk.GenerateKey(EllipticalCurve.P256, true, SignatureAlgorithm.EcdsaSha256);
            var canonicalizedKey = (ECJwk)CanonicalizeKey(jwk);

            Assert.True(canonicalizedKey.D.IsEmpty);

            Assert.Equal(EllipticalCurve.P256.Id, canonicalizedKey.Crv.Id);
            Assert.False(canonicalizedKey.X.IsEmpty);
            Assert.False(canonicalizedKey.Y.IsEmpty);
        }

        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override void IsSupportedKeyWrapping_Success(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            Assert.True(key.SupportKeyManagement(alg));
            Assert.False(key.SupportEncryption(enc));
        }

        [Theory]
        [MemberData(nameof(GetValidSignatureKeys))]
        public override void IsSupportedSignature_Success(Jwk key, SignatureAlgorithm alg)
        {
            Assert.True(key.SupportSignature(alg));
        }

        public static IEnumerable<object[]> GetWrappingKeys()
        {
            yield return new object[] { PrivateEcc256Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW };
            yield return new object[] { PrivateEcc256Key, EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.EcdhEsAes192KW };
            yield return new object[] { PrivateEcc256Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEsAes256KW };
            yield return new object[] { PrivateEcc256Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEs };

            yield return new object[] { PrivateEcc384Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW };
            yield return new object[] { PrivateEcc384Key, EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.EcdhEsAes192KW };
            yield return new object[] { PrivateEcc384Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEsAes256KW };
            yield return new object[] { PrivateEcc384Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEs };

            yield return new object[] { PrivateEcc521Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.EcdhEsAes128KW };
            yield return new object[] { PrivateEcc521Key, EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.EcdhEsAes192KW };
            yield return new object[] { PrivateEcc521Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEsAes256KW };
            yield return new object[] { PrivateEcc521Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.EcdhEs };
        }

        public static IEnumerable<object[]> GetValidSignatureKeys()
        {
            yield return new object[] { PublicEcc256Key, SignatureAlgorithm.EcdsaSha256 };

            yield return new object[] { PublicEcc384Key, SignatureAlgorithm.EcdsaSha384 };

            yield return new object[] { PublicEcc521Key, SignatureAlgorithm.EcdsaSha512 };
            
            yield return new object[] { PublicEcc256XKey, SignatureAlgorithm.EcdsaSha256K };

            yield return new object[] { PrivateEcc256Key, SignatureAlgorithm.EcdsaSha256 };

            yield return new object[] { PrivateEcc384Key, SignatureAlgorithm.EcdsaSha384 };

            yield return new object[] { PrivateEcc521Key, SignatureAlgorithm.EcdsaSha512 };
            
            yield return new object[] { PrivateEcc256XKey, SignatureAlgorithm.EcdsaSha256K };
        }

        public static IEnumerable<object[]> GetInvalidKeys()
        {
            yield return new object[] { PrivateEcc256Key, SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { PrivateEcc256Key, SignatureAlgorithm.EcdsaSha512 };
            yield return new object[] { PrivateEcc256Key, SignatureAlgorithm.EcdsaSha256K };

            yield return new object[] { PrivateEcc384Key, SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { PrivateEcc384Key, SignatureAlgorithm.EcdsaSha512 };
            yield return new object[] { PrivateEcc384Key, SignatureAlgorithm.EcdsaSha256K };

            yield return new object[] { PrivateEcc521Key, SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { PrivateEcc521Key, SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { PrivateEcc521Key, SignatureAlgorithm.EcdsaSha256X };

            yield return new object[] { PrivateEcc256XKey, SignatureAlgorithm.EcdsaSha256 };
            yield return new object[] { PrivateEcc256XKey, SignatureAlgorithm.EcdsaSha384 };
            yield return new object[] { PrivateEcc256XKey, SignatureAlgorithm.EcdsaSha512 };
        }

        [Theory]
        [InlineData("P-256", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}")]
        [InlineData("P-256", "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}")]
        [InlineData("P-256", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"object\":{\"property\":true},\"float\":123.456,\"integer\":1234,\"boolean\":true,\"string\":\"hello\",\"null\":null,\"array\":[\"string\", 1, true, false, null, {}, [0]]}")]
        [InlineData("P-256", "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"object\":{\"property\":true},\"float\":123.456,\"integer\":1234,\"boolean\":true,\"string\":\"hello\",\"null\":null,\"array\":[\"string\", 1, true, false, null, {}, [0]]}")]
        [InlineData("secp256k1", "{\"crv\":\"secp256k1\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"object\":{\"property\":true},\"float\":123.456,\"integer\":1234,\"boolean\":true,\"string\":\"hello\",\"null\":null,\"array\":[\"string\", 1, true, false, null, {}, [0]]}")]
        public void FromJson(string crvName, string json)
        {
            // https://tools.ietf.org/html/rfc7517#appendix-A.1
            var key = Jwk.FromJson(json);
            Assert.NotNull(key);
            var jwk = Assert.IsType<ECJwk>(key);

            Assert.Equal("1", jwk.Kid);
            Assert.True(JwkUseNames.Enc.SequenceEqual(jwk.Use));

            Assert.Equal(Encoding.UTF8.GetBytes(crvName), jwk.Crv.Name);
            Assert.Equal(jwk.X.ToArray(), Base64Url.Decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"));
            Assert.Equal(jwk.Y.ToArray(), Base64Url.Decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"));
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
            key.Use = JwkUseNames.Sig;
            key.X5t = Base64Url.Decode("dGhpcyBpcyBhIFNIQTEgdGVzdCE");
            key.X5tS256 = Base64Url.Decode("dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA");
            key.X5u = "https://example.com";
            key.X5c.Add(Convert.FromBase64String("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="));

            using var bufferWriter = new PooledByteBufferWriter();
            key.Serialize(bufferWriter);
            var json = Encoding.UTF8.GetString(bufferWriter.WrittenSpan.ToArray());

            Assert.Contains("\"kid\":\"kid-ec\"", json);
            Assert.Contains("\"key_ops\":[\"sign\"]", json);
            Assert.Contains("\"use\":\"sig\"", json);
            Assert.Contains("\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\"", json);
            Assert.Contains("\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\"", json);
#if NETSTANDARD2_0
            Assert.Contains("\"x5u\":\"" + JsonEncodedText.Encode("https://example.com") + "\"", json);
            Assert.Contains("\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K\u002bIiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel\u002bW1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW\u002boyVVkaZdklLQp2Btgt9qr21m42f4wTw\u002bXrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL\u002b9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo\u002bOwb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk\u002bfbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C\u002b2qok\u002b2\u002bqDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR\u002bN5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"]", json);
#else
            Assert.Contains("\"x5u\":\"" + JsonEncodedText.Encode("https://example.com", Constants.JsonEncoder) + "\"", json);
            Assert.Contains("\"x5c\":[\"" + JsonEncodedText.Encode("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==", Constants.JsonEncoder) + "\"]", json);
#endif

            Assert.Contains("\"crv\":\"P-256\"", json);
            Assert.Contains("\"x\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.X)) + "\"", json);
            Assert.Contains("\"y\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.Y)) + "\"", json);
            Assert.Contains("\"d\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.D)) + "\"", json);
        }

        private const string Pkcs8PemECPrivateKey = @"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcKEsLbFoRe1W/2jP
whpHKz8E19aFG/Y0ny19WzRSs4qhRANCAASBAezkdGSm6tcM9ppuK9PYhpGjJi0i
y6T3Y16v8maAqNihK6YdWZI19n2ctNWPF4PTykPnjwpauqYkB5k2wMOp
-----END PRIVATE KEY-----";
        private const string Pkcs1PemECPrivateKey = @"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHChLC2xaEXtVv9oz8IaRys/BNfWhRv2NJ8tfVs0UrOKoAoGCCqGSM49
AwEHoUQDQgAEgQHs5HRkpurXDPaabivT2IaRoyYtIsuk92Ner/JmgKjYoSumHVmS
NfZ9nLTVjxeD08pD548KWrqmJAeZNsDDqQ==
-----END EC PRIVATE KEY-----";
        private const string Pkcs8PemECPublicKey = @"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgQHs5HRkpurXDPaabivT2IaRoyYt
Isuk92Ner/JmgKjYoSumHVmSNfZ9nLTVjxeD08pD548KWrqmJAeZNsDDqQ==
-----END PUBLIC KEY-----";

        [Theory]
        [InlineData(Pkcs1PemECPrivateKey)]
        [InlineData(Pkcs8PemECPrivateKey)]
        public void FromPem_PrivateKey(string pem)
        {
            var key = ECJwk.FromPem(pem);
            ECParameters ecParameters = key.ExportParameters(true);
            ECParameters expected = GetNistP256ReferenceKey();
            AssertEqual(expected, ecParameters);
            Assert.True(key.HasPrivateKey);
        }

        [Theory]
        [InlineData(Pkcs8PemECPublicKey)]
        public void FromPem_PublicKey(string pem)
        {
            var key = ECJwk.FromPem(pem);
            ECParameters ecParameters = key.ExportParameters(true);
            ECParameters expected = GetNistP256ReferenceKey(false);
            AssertEqual(expected, ecParameters);
            Assert.False(key.HasPrivateKey);
        }

        [Fact]
        public void FromPem_UnexpectedKeyType_ThrowArgumentException()
        {
            string pem = @"
-----BEGIN RSA PUBLIC KEY-----
MEgCQQC3P1n17ovVXiS3/wKa0WqFQ8ltJT5UMZuTUyxBw8FHe4nbLS8z17modFhI
4GqOaDtQRFEeG8o2JSfhfPQrOAYVAgMBAAE=
-----END RSA PUBLIC KEY-----";

            Assert.Throws<InvalidOperationException>(() => ECJwk.FromPem(pem));
        }

        internal static void AssertEqual(in ECParameters p1, in ECParameters p2)
        {
            ComparePrivateKey(p1, p2);
            ComparePublicKey(p1.Q, p2.Q);
            CompareCurve(p1.Curve, p2.Curve);
        }

        internal static void ComparePrivateKey(in ECParameters p1, in ECParameters p2, bool isEqual = true)
        {
            if (isEqual)
            {
                Assert.Equal(p1.D, p2.D);
            }
            else
            {
                Assert.NotEqual(p1.D, p2.D);
            }
        }

        internal static void ComparePublicKey(in ECPoint q1, in ECPoint q2, bool isEqual = true)
        {
            if (isEqual)
            {
                Assert.Equal(q1.X, q2.X);
                Assert.Equal(q1.Y, q2.Y);
            }
            else
            {
                Assert.NotEqual(q1.X, q2.X);
                Assert.NotEqual(q1.Y, q2.Y);
            }
        }

        internal static void CompareCurve(in ECCurve c1, in ECCurve c2)
        {
            if (c1.IsNamed)
            {
                Assert.True(c2.IsNamed);

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || string.IsNullOrEmpty(c1.Oid.Value))
                {
                    Assert.Equal(c1.Oid.FriendlyName, c2.Oid.FriendlyName);
                }
                else
                {
                    Assert.Equal(c1.Oid.Value, c2.Oid.Value);
                }
            }
            else if (c1.IsExplicit)
            {
                Assert.True(c2.IsExplicit);
                Assert.Equal(c1.A, c2.A);
                Assert.Equal(c1.B, c2.B);
                Assert.Equal(c1.CurveType, c2.CurveType);
                Assert.Equal(c1.G.X, c2.G.X);
                Assert.Equal(c1.G.Y, c2.G.Y);
                Assert.Equal(c1.Cofactor, c2.Cofactor);
                Assert.Equal(c1.Order, c2.Order);

                // Optional parameters. Null is an OK interpretation.
                // Different is not.
                if (c1.Seed != null && c2.Seed != null)
                {
                    Assert.Equal(c1.Seed, c2.Seed);
                }

                if (c1.Hash != null && c2.Hash != null)
                {
                    Assert.Equal(c1.Hash, c2.Hash);
                }

                if (c1.IsPrime)
                {
                    Assert.True(c2.IsPrime);
                    Assert.Equal(c1.Prime, c2.Prime);
                }
                else if (c1.IsCharacteristic2)
                {
                    Assert.True(c2.IsCharacteristic2);
                    Assert.Equal(c1.Polynomial, c2.Polynomial);
                }
            }
        }

        internal static ECParameters GetNistP256ReferenceKey(bool includePrivateKey = true)
        {
            // From Suite B Implementers's Guide to FIPS 186-3 (ECDSA)
            // Section D.1.1
            ECParameters parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q =
                {
                    X = "8101ECE47464A6EAD70CF69A6E2BD3D88691A3262D22CBA4F7635EAFF26680A8".HexToByteArray(),
                    Y = "D8A12BA61D599235F67D9CB4D58F1783D3CA43E78F0A5ABAA624079936C0C3A9".HexToByteArray(),
                }
            };

            if (includePrivateKey)
            {
                parameters.D = "70A12C2DB16845ED56FF68CFC21A472B3F04D7D6851BF6349F2D7D5B3452B38A".HexToByteArray();
            }
            return parameters;
        }

        private static ECJwk PrivateEcc256Key => new ECJwk
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        );

        private static ECJwk PrivateEcc256XKey => new ECJwk
        (
            crv: EllipticalCurve.Secp256k1,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        );

        private static ECJwk PublicEcc256Key => new ECJwk
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        );
        

        private static ECJwk PublicEcc256XKey => new ECJwk
        (
            crv: EllipticalCurve.Secp256k1,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        );

        private static ECJwk PublicEcc384Key => new ECJwk
        (
            crv: EllipticalCurve.P384,
            d: "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            x: "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            y: "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        );

        private static ECJwk PrivateEcc384Key => new ECJwk
        (
            crv: EllipticalCurve.P384,
            d: "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            x: "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            y: "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        );

        private static ECJwk PrivateEcc521Key => new ECJwk
        (
            crv: EllipticalCurve.P521,
            d: "Adri8PbGJBWN5upp_67cKF8E0ADCF-w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HISTMh_RSmFFhTfBH",
            x: "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            y: "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        );

        private static ECJwk PublicEcc521Key => new ECJwk
        (
            crv: EllipticalCurve.P521,
            x: "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            y: "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        );
    }
}
#endif