using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class PasswordBasedJwkTests : JwkTestsBase
    {
        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override KeyWrapper CreateKeyWrapper_Succeed(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            return base.CreateKeyWrapper_Succeed(key, enc, alg);
        }

        [Fact]
        public override void Canonicalize()
        {
            var jwk = PasswordBasedJwk.FromPassphrase("Thus from my lips, by yours, my sin is purged.");
            var canonicalizedKey = (SymmetricJwk)CanonicalizeKey(jwk);
            Assert.NotEmpty(canonicalizedKey.ToArray());
        }

        [Theory]
        [MemberData(nameof(GetWrappingKeys))]
        public override void IsSupportedKeyWrapping_Success(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            base.IsSupportedKeyWrapping_Success(key, enc, alg);
        }

        public static IEnumerable<object[]> GetWrappingKeys()
        {
            yield return new object[] { _key, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.Pbes2HS256A128KW };
            yield return new object[] { _key, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.Pbes2HS384A192KW };
            yield return new object[] { _key, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.Pbes2HS512A256KW };
            yield return new object[] { _key, EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.Pbes2HS256A128KW };
            yield return new object[] { _key, EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.Pbes2HS384A192KW };
            yield return new object[] { _key, EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.Pbes2HS512A256KW };
            yield return new object[] { _key, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.Pbes2HS256A128KW };
            yield return new object[] { _key, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.Pbes2HS384A192KW };
            yield return new object[] { _key, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.Pbes2HS512A256KW };
#if SUPPORT_AESGCM
            yield return new object[] { _key, EncryptionAlgorithm.A128Gcm, KeyManagementAlgorithm.Pbes2HS256A128KW };
            yield return new object[] { _key, EncryptionAlgorithm.A128Gcm, KeyManagementAlgorithm.Pbes2HS384A192KW };
            yield return new object[] { _key, EncryptionAlgorithm.A128Gcm, KeyManagementAlgorithm.Pbes2HS512A256KW };
            yield return new object[] { _key, EncryptionAlgorithm.A192Gcm, KeyManagementAlgorithm.Pbes2HS256A128KW };
            yield return new object[] { _key, EncryptionAlgorithm.A192Gcm, KeyManagementAlgorithm.Pbes2HS384A192KW };
            yield return new object[] { _key, EncryptionAlgorithm.A192Gcm, KeyManagementAlgorithm.Pbes2HS512A256KW };
            yield return new object[] { _key, EncryptionAlgorithm.A256Gcm, KeyManagementAlgorithm.Pbes2HS256A128KW };
            yield return new object[] { _key, EncryptionAlgorithm.A256Gcm, KeyManagementAlgorithm.Pbes2HS384A192KW };
            yield return new object[] { _key, EncryptionAlgorithm.A256Gcm, KeyManagementAlgorithm.Pbes2HS512A256KW };
#endif
        }

        [Fact]
        public override void WriteTo()
        {
            var key = PasswordBasedJwk.FromPassphrase("Thus from my lips, by yours, my sin is purged.");
            key.Kid = JsonEncodedText.Encode("kid1");
            key.KeyOps.Add(JwkKeyOpsValues.Sign);
            key.Use = JwkUseValues.Sig;
            key.X5t = Base64Url.Decode("dGhpcyBpcyBhIFNIQTEgdGVzdCE");
            key.X5tS256 = Base64Url.Decode("dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICA");
            key.X5u = "https://example.com";
            key.X5c.Add(Convert.FromBase64String("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="));

            using var bufferWriter = new PooledByteBufferWriter();
            key.Serialize(bufferWriter);
            var json = Encoding.UTF8.GetString(bufferWriter.WrittenSpan.ToArray());

            Assert.Contains("\"kid\":\"kid1\"", json);
            Assert.Contains("\"key_ops\":[\"sign\"]", json);
            Assert.Contains("\"use\":\"sig\"", json);
            Assert.Contains("\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\"", json);
            Assert.Contains("\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICA\"", json);
#if NETSTANDARD2_0
            Assert.Contains("\"x5u\":\"" + JsonEncodedText.Encode("https://example.com") + "\"", json);
            Assert.Contains("\"x5c\":[\"" + JsonEncodedText.Encode("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==") + "\"]", json);
#else
            Assert.Contains("\"x5u\":\"" + JsonEncodedText.Encode("https://example.com", JsonSerializationBehavior.JsonEncoder) + "\"", json);
            Assert.Contains("\"x5c\":[\"" + JsonEncodedText.Encode("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==", JsonSerializationBehavior.JsonEncoder) + "\"]", json);
#endif
            Assert.Contains("\"k\":\"" + Encoding.UTF8.GetString(Base64Url.Encode(key.ToArray())) + "\"", json);
        }

        public override void FromJson_WithProperties(string json)
        {
            // No test
        }

        private static PasswordBasedJwk _key = PasswordBasedJwk.FromPassphrase("Thus from my lips, by yours, my sin is purged.");
    }
}
