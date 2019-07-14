using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class SymmetricJwkTests : JwkTestsBase
    {
        [Theory]
        [MemberData(nameof(GetEncryptionKeys))]
        public override AuthenticatedEncryptor CreateAuthenticatedEncryptor_Succeed(Jwk key, EncryptionAlgorithm enc)
        {
            return base.CreateAuthenticatedEncryptor_Succeed(key, enc);
        }

        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override KeyWrapper CreateKeyWrapper_Succeed(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            return base.CreateKeyWrapper_Succeed(key, enc, alg);
        }

        [Theory]
        [MemberData(nameof(GetSignatureKeys))]
        public override Signer CreateSigner_Succeed(Jwk key, SignatureAlgorithm alg)
        {
            return base.CreateSigner_Succeed(key, alg);
        }

        [Fact]
        public override void Canonicalize()
        {
            var jwk = SymmetricJwk.GenerateKey(256);
            var canonicalizedKey = (SymmetricJwk)CanonicalizeKey(jwk);
            Assert.NotEqual(0, canonicalizedKey.K.Length);
        }

        [Theory]
        [MemberData(nameof(GetEncryptionKeys))]
        public override void IsSupportedEncryption_Success(Jwk key, EncryptionAlgorithm enc)
        {
            base.IsSupportedEncryption_Success(key, enc);
        }

        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override void IsSupportedKeyWrapping_Success(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            base.IsSupportedKeyWrapping_Success(key, enc, alg);
        }

        [Theory]
        [MemberData(nameof(GetSignatureKeys))]
        public override void IsSupportedSignature_Success(Jwk key, SignatureAlgorithm alg)
        {
            base.IsSupportedSignature_Success(key, alg);
        }

        public static IEnumerable<object[]> GetEncryptionKeys()
        {
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes128CbcHmacSha256 };
            yield return new object[] { _symmetric384Key, EncryptionAlgorithm.Aes192CbcHmacSha384 };
            yield return new object[] { _symmetric512Key, EncryptionAlgorithm.Aes256CbcHmacSha512 };
#if NETCOREAPP3_0
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes128Gcm };
            yield return new object[] { _symmetric384Key, EncryptionAlgorithm.Aes192Gcm };
            yield return new object[] { _symmetric512Key, EncryptionAlgorithm.Aes256Gcm };
#endif
        }

        public static IEnumerable<object[]> GetWrappingKeys()
        {
            yield return new object[] { _symmetric128Key, EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { _symmetric192Key, EncryptionAlgorithm.Aes192CbcHmacSha384, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes256CbcHmacSha512, KeyManagementAlgorithm.Aes256KW };
#if NETCOREAPP3_0
            yield return new object[] { _symmetric128Key, EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.Aes128GcmKW };
            yield return new object[] { _symmetric192Key, EncryptionAlgorithm.Aes192Gcm, KeyManagementAlgorithm.Aes192GcmKW };
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes256Gcm, KeyManagementAlgorithm.Aes256GcmKW };
            yield return new object[] { _symmetric128Key, EncryptionAlgorithm.Aes128Gcm, KeyManagementAlgorithm.Aes128KW };
            yield return new object[] { _symmetric192Key, EncryptionAlgorithm.Aes192Gcm, KeyManagementAlgorithm.Aes192KW };
            yield return new object[] { _symmetric256Key, EncryptionAlgorithm.Aes256Gcm, KeyManagementAlgorithm.Aes256KW };
#endif
        }

        public static IEnumerable<object[]> GetSignatureKeys()
        {
            yield return new object[] { _symmetric128Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric192Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric256Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric384Key, SignatureAlgorithm.HmacSha256 };
            yield return new object[] { _symmetric512Key, SignatureAlgorithm.HmacSha256 };

            yield return new object[] { _symmetric128Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric192Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric256Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric384Key, SignatureAlgorithm.HmacSha384 };
            yield return new object[] { _symmetric512Key, SignatureAlgorithm.HmacSha384 };

            yield return new object[] { _symmetric128Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric192Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric256Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric384Key, SignatureAlgorithm.HmacSha512 };
            yield return new object[] { _symmetric512Key, SignatureAlgorithm.HmacSha512 };
        }

        [Theory]
        [InlineData("{\"kty\":\"oct\",\"alg\":\"A128KW\",\"use\":\"sig\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kid\":\"kid1\"}")]
        [InlineData("{\"alg\":\"A128KW\",\"kty\":\"oct\",\"use\":\"sig\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kid\":\"kid1\"}")]
        [InlineData("{\"kty\":\"oct\",\"alg\":\"A128KW\",\"use\":\"sig\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kid\":\"kid1\"},\"object\":{\"property\":true},\"float\":123.456,\"integer\":1234,\"boolean\":true,\"string\":\"hello\",\"null\":null,\"array\":[\"string\", 1, true, false, null, {}, [0]]")]
        [InlineData("{\"alg\":\"A128KW\",\"kty\":\"oct\",\"use\":\"sig\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kid\":\"kid1\"},\"object\":{\"property\":true},\"float\":123.456,\"integer\":1234,\"boolean\":true,\"string\":\"hello\",\"null\":null,\"array\":[\"string\", 1, true, false, null, {}, [0]]")]
        public override void FromJson(string json)
        {
            var key = Jwk.FromJson(json);
            Assert.NotNull(key);
            var jwk = Assert.IsType<SymmetricJwk>(key);

            Assert.Equal(KeyManagementAlgorithm.Aes128KW.Utf8Name, jwk.Alg);
            Assert.Equal("kid1", jwk.Kid);
            Assert.True(jwk.K.SequenceEqual(Base64Url.Decode("GawgguFyGrWKav7AX4VKUg")));
            Assert.True(JwkUseNames.Sig.SequenceEqual(jwk.Use));
        }

        [Theory]
        [InlineData("{\"kty\":\"oct\",\"alg\":\"A128KW\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kid\":\"kid1\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"],\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\",\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\",\"key_ops\":[\"sign\"],\"x5u\":\"https://example.com\"}")]
        [InlineData("{\"alg\":\"A128KW\",\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kid\":\"kid1\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"],\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\",\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\",\"key_ops\":[\"sign\"],\"x5u\":\"https://example.com\"}")]
        public override void FromJson_WithProperties(string json)
        {
            // https://tools.ietf.org/html/rfc7517#appendix-B
            var key = Jwk.FromJson(json);
            Assert.NotNull(key);
            var jwk = Assert.IsType<SymmetricJwk>(key);

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
            var key = SymmetricJwk.GenerateKey(256, SignatureAlgorithm.HmacSha256);
            key.Kid = "kid1";
            key.KeyOps.Add("sign");
            key.Use = JwkUseNames.Sig.ToArray();
            key.X5t = Base64Url.Decode("dGhpcyBpcyBhIFNIQTEgdGVzdCE");
            key.X5tS256 = Base64Url.Decode("dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA");
            key.X5u = "https://example.com";
            key.X5c.Add(Convert.FromBase64String("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="));

            using (var bufferWriter = new ArrayBufferWriter())
            {
                key.Serialize(bufferWriter);
                var json = Encoding.UTF8.GetString(bufferWriter.WrittenSpan);

                Assert.Contains("\"kid\":\"kid1\"", json);
                Assert.Contains("\"key_ops\":[\"sign\"]", json);
                Assert.Contains("\"use\":\"sig\"", json);
                Assert.Contains("\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\"", json);
                Assert.Contains("\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICAgIA\"", json);
                Assert.Contains("\"x5u\":\"" + JsonEncodedText.Encode("https://example.com") + "\"", json);
                Assert.Contains("\"x5c\":[\"" + JsonEncodedText.Encode("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==") + "\"]", json);

                Assert.Contains("\"k\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.K)) + "\"", json);
            }
        }

        private static SymmetricJwk _symmetric128Key => new SymmetricJwk("LxOcGxlu169Vxa1A7HyelQ");

        private static SymmetricJwk _symmetric192Key => new SymmetricJwk("kVdKe3BiLcrc7LujDzaD-3EdZCVTStnc");

        private static SymmetricJwk _symmetric256Key => new SymmetricJwk("-PYUNdvLXVnc8yJQw7iQkSlNmAb202ZO-rfCyrAc1Lo");

        private static SymmetricJwk _symmetric384Key => new SymmetricJwk("V4hBa9WfvqqZ4ZWfm2oIoKZaCdy_FEf9cPXMwFSSOivAUMqs931xgQ-fSjTfB9tm");

        private static SymmetricJwk _symmetric512Key => new SymmetricJwk("98TDxdDvd5mKZNFitgMCwH_z7nzKS6sk_vykNTowymsJ4e8eGviJnVWI9i-YLreuBfhHDhis3CY2aKoK1RT6sg");
    }
}
