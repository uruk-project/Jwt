#if !NET461
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JsonWebToken.Cryptography;
using JsonWebToken.Tests.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class ECJwkTests : JwkTestsBase
    {
        [Fact]
        public void Factory()
        {
            var x = Base64Url.Decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
            var y = Base64Url.Decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
            var d = Base64Url.Decode("TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR01");

            // FromBase64Url
            var key = ECJwk.FromBase64Url(EllipticalCurve.P256, x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", KeyManagementAlgorithm.EcdhEs, computeThumbprint: true);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.Equal(0, key.D.Length);
            Assert.NotEqual(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromBase64Url(EllipticalCurve.P256, x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", KeyManagementAlgorithm.EcdhEs, computeThumbprint: false);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.Equal(0, key.D.Length);
            Assert.Equal(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromBase64Url(EllipticalCurve.P256, x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", d: "TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR01", KeyManagementAlgorithm.EcdhEs, computeThumbprint: true);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.True(key.D.SequenceEqual(d));
            Assert.NotEqual(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromBase64Url(EllipticalCurve.P256, x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", d: "TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR01", KeyManagementAlgorithm.EcdhEs, computeThumbprint: false);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.True(key.D.SequenceEqual(d));
            Assert.Equal(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromBase64Url(EllipticalCurve.P256, x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", SignatureAlgorithm.ES256, computeThumbprint: true);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.Equal(0, key.D.Length);
            Assert.NotEqual(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromBase64Url(EllipticalCurve.P256, x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", SignatureAlgorithm.ES256, computeThumbprint: false);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.Equal(0, key.D.Length);
            Assert.Equal(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromBase64Url(EllipticalCurve.P256, x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", d: "TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR01", SignatureAlgorithm.ES256, computeThumbprint: true);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.True(key.D.SequenceEqual(d));
            Assert.NotEqual(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromBase64Url(EllipticalCurve.P256, x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", d: "TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR01", SignatureAlgorithm.ES256, computeThumbprint: false);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.True(key.D.SequenceEqual(d));
            Assert.Equal(0, key.Kid.EncodedUtf8Bytes.Length);


            // FromByteArray
            key = ECJwk.FromByteArray(EllipticalCurve.P256, x: x, y: y, KeyManagementAlgorithm.EcdhEs, computeThumbprint: true);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.Equal(0, key.D.Length);
            Assert.NotEqual(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromByteArray(EllipticalCurve.P256, x: x, y: y, KeyManagementAlgorithm.EcdhEs, computeThumbprint: false);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.Equal(0, key.D.Length);
            Assert.Equal(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromByteArray(EllipticalCurve.P256, x: x, y: y, d: d, KeyManagementAlgorithm.EcdhEs, computeThumbprint: true);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.True(key.D.SequenceEqual(d));
            Assert.NotEqual(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromByteArray(EllipticalCurve.P256, x: x, y: y, d: d, KeyManagementAlgorithm.EcdhEs, computeThumbprint: false);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.True(key.D.SequenceEqual(d));
            Assert.Equal(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromByteArray(EllipticalCurve.P256, x: x, y: y, SignatureAlgorithm.ES256, computeThumbprint: true);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.Equal(0, key.D.Length);
            Assert.NotEqual(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromByteArray(EllipticalCurve.P256, x: x, y: y, SignatureAlgorithm.ES256, computeThumbprint: false);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.Equal(0, key.D.Length);
            Assert.Equal(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromByteArray(EllipticalCurve.P256, x: x, y: y, d: d, SignatureAlgorithm.ES256, computeThumbprint: true);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.True(key.D.SequenceEqual(d));
            Assert.NotEqual(0, key.Kid.EncodedUtf8Bytes.Length);

            key = ECJwk.FromByteArray(EllipticalCurve.P256, x: x, y: y, d: d, SignatureAlgorithm.ES256, computeThumbprint: false);
            Assert.True(key.X.SequenceEqual(x));
            Assert.True(key.Y.SequenceEqual(y));
            Assert.True(key.D.SequenceEqual(d));
            Assert.Equal(0, key.Kid.EncodedUtf8Bytes.Length);
        }

        [Theory]
        [MemberData(nameof(SupportedCurves))]
        public void Equal(EllipticalCurve crv)
        {
            var key = ECJwk.GeneratePrivateKey(crv);
            Assert.True(key.Equals(key));
            Assert.Equal(key, key);
            var publicKey = key.AsPublicKey();
            Assert.NotEqual(key, publicKey);
            var copiedKey = ECJwk.FromJson(key.ToString());
            Assert.Equal(key, copiedKey);

            // 'kid' is not a discriminant, excepted if the value is different.
            copiedKey.Kid = default;
            Assert.Equal(key, copiedKey);
            Assert.Equal(copiedKey, key);
            key.Kid = default;
            Assert.Equal(key, copiedKey);
            key.Kid = JsonEncodedText.Encode("X");
            copiedKey.Kid = JsonEncodedText.Encode("Y");
            Assert.NotEqual(key, copiedKey);

            Assert.NotEqual(key, Jwk.None);
        }

        [Theory]
        [MemberData(nameof(SupportedCurves))]
        public void GenerateKey(EllipticalCurve crv)
        {
            var key = ECJwk.GeneratePrivateKey(crv);
            Assert.NotNull(key);

            var key2 = ECJwk.GeneratePrivateKey(crv.SupportedSignatureAlgorithm);
            Assert.NotNull(key2);
        }

        public static IEnumerable<object[]> SupportedCurves => EllipticalCurve.SupportedCurves.Select(c => new object[] { c }).ToArray();

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

        [Theory]
        [InlineData("ES256")]
        [InlineData("ES384")]
        [InlineData("ES512")]
        [InlineData("ES256K")]
        public override void Canonicalize(string alg)
        {
            var jwk = ECJwk.GeneratePrivateKey((SignatureAlgorithm)alg);
            var canonicalizedKey = (ECJwk)CanonicalizeKey(jwk);

            Assert.True(canonicalizedKey.D.IsEmpty);
            bool supported = EllipticalCurve.TryGetSupportedCurve((SignatureAlgorithm)alg, out var crv);

            Assert.True(supported);
            Assert.Equal(crv.Id, canonicalizedKey.Crv.Id);
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
            yield return new object[] { PrivateEcc256Key, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.EcdhEsA128KW };
            yield return new object[] { PrivateEcc256Key, EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.EcdhEsA192KW };
            yield return new object[] { PrivateEcc256Key, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.EcdhEsA256KW };
            yield return new object[] { PrivateEcc256Key, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.EcdhEs };

            yield return new object[] { PrivateEcc384Key, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.EcdhEsA128KW };
            yield return new object[] { PrivateEcc384Key, EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.EcdhEsA192KW };
            yield return new object[] { PrivateEcc384Key, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.EcdhEsA256KW };
            yield return new object[] { PrivateEcc384Key, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.EcdhEs };

            yield return new object[] { PrivateEcc521Key, EncryptionAlgorithm.A128CbcHS256, KeyManagementAlgorithm.EcdhEsA128KW };
            yield return new object[] { PrivateEcc521Key, EncryptionAlgorithm.A192CbcHS384, KeyManagementAlgorithm.EcdhEsA192KW };
            yield return new object[] { PrivateEcc521Key, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.EcdhEsA256KW };
            yield return new object[] { PrivateEcc521Key, EncryptionAlgorithm.A256CbcHS512, KeyManagementAlgorithm.EcdhEs };
        }

        public static IEnumerable<object[]> GetValidSignatureKeys()
        {
            yield return new object[] { PublicEcc256Key, SignatureAlgorithm.ES256 };

            yield return new object[] { PublicEcc384Key, SignatureAlgorithm.ES384 };

            yield return new object[] { PublicEcc521Key, SignatureAlgorithm.ES512 };

            yield return new object[] { PublicEcc256KKey, SignatureAlgorithm.ES256K };

            yield return new object[] { PrivateEcc256Key, SignatureAlgorithm.ES256 };

            yield return new object[] { PrivateEcc384Key, SignatureAlgorithm.ES384 };

            yield return new object[] { PrivateEcc521Key, SignatureAlgorithm.ES512 };

            yield return new object[] { PrivateEcc256KKey, SignatureAlgorithm.ES256K };
        }

        public static IEnumerable<object[]> GetInvalidKeys()
        {
            yield return new object[] { PrivateEcc256Key, SignatureAlgorithm.ES384 };
            yield return new object[] { PrivateEcc256Key, SignatureAlgorithm.ES512 };
            yield return new object[] { PrivateEcc256Key, SignatureAlgorithm.ES256K };

            yield return new object[] { PrivateEcc384Key, SignatureAlgorithm.ES256 };
            yield return new object[] { PrivateEcc384Key, SignatureAlgorithm.ES512 };
            yield return new object[] { PrivateEcc384Key, SignatureAlgorithm.ES256K };

            yield return new object[] { PrivateEcc521Key, SignatureAlgorithm.ES256 };
            yield return new object[] { PrivateEcc521Key, SignatureAlgorithm.ES384 };
            yield return new object[] { PrivateEcc521Key, SignatureAlgorithm.ES256K };

            yield return new object[] { PrivateEcc256KKey, SignatureAlgorithm.ES256 };
            yield return new object[] { PrivateEcc256KKey, SignatureAlgorithm.ES384 };
            yield return new object[] { PrivateEcc256KKey, SignatureAlgorithm.ES512 };
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

            Assert.Equal("1", jwk.Kid.ToString());
            Assert.True(JwkUseValues.Enc.Equals(jwk.Use));

            Assert.Equal(crvName, jwk.Crv.Name.ToString());
            Assert.Equal(jwk.X.ToArray(), Base64Url.Decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"));
            Assert.Equal(jwk.Y.ToArray(), Base64Url.Decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"));
        }

        [Theory]
        [InlineData("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"],\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\",\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICA\",\"key_ops\":[\"sign\"],\"x5u\":\"https://example.com\"}")]
        [InlineData("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"],\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\",\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICA\",\"key_ops\":[\"sign\"],\"x5u\":\"https://example.com\"}")]
        public override void FromJson_WithProperties(string json)
        {
            var key = Jwk.FromJson(json);
            Assert.NotNull(key);
            var jwk = Assert.IsType<ECJwk>(key);

            Assert.NotNull(jwk.X509CertificateChain);
            Assert.NotEmpty(jwk.X509CertificateChain);
            Assert.NotEmpty(jwk.X5c);

            Assert.Equal(Base64Url.Decode("dGhpcyBpcyBhIFNIQTEgdGVzdCE"), jwk.X5t);
            Assert.Equal(Base64Url.Decode("dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICA"), jwk.X5tS256);
            Assert.Equal(JwkKeyOpsValues.Sign, jwk.KeyOps[0]);
            Assert.Equal("https://example.com", jwk.X5u);
        }

        [Fact]
        public override void WriteTo()
        {
            var key = ECJwk.GeneratePrivateKey(SignatureAlgorithm.ES256);
            key.Kid = JsonEncodedText.Encode("kid-ec");
            key.KeyOps.Add(JwkKeyOpsValues.Sign);
            key.Use = JwkUseValues.Sig;
            key.X5t = Base64Url.Decode("dGhpcyBpcyBhIFNIQTEgdGVzdCE");
            key.X5tS256 = Base64Url.Decode("dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICA");
            key.X5u = "https://example.com";
            key.X5c.Add(Convert.FromBase64String("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="));

            using var bufferWriter = new PooledByteBufferWriter();
            key.Serialize(bufferWriter);
            var json = Encoding.UTF8.GetString(bufferWriter.WrittenSpan.ToArray());

            Assert.Contains("\"kid\":\"kid-ec\"", json);
            Assert.Contains("\"key_ops\":[\"sign\"]", json);
            Assert.Contains("\"use\":\"sig\"", json);
            Assert.Contains("\"x5t\":\"dGhpcyBpcyBhIFNIQTEgdGVzdCE\"", json);
            Assert.Contains("\"x5t#S256\":\"dGhpcyBpcyBhIFNIQTI1NiB0ZXN0ISAgICAgICAgICA\"", json);
#if NETSTANDARD2_0
            Assert.Contains("\"x5u\":\"" + JsonEncodedText.Encode("https://example.com") + "\"", json);
            Assert.Contains("\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K\u002bIiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel\u002bW1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW\u002boyVVkaZdklLQp2Btgt9qr21m42f4wTw\u002bXrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL\u002b9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo\u002bOwb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk\u002bfbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C\u002b2qok\u002b2\u002bqDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR\u002bN5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"]", json);
#else
            Assert.Contains("\"x5u\":\"" + JsonEncodedText.Encode("https://example.com", JsonSerializationBehavior.JsonEncoder) + "\"", json);
            Assert.Contains("\"x5c\":[\"" + JsonEncodedText.Encode("MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==", JsonSerializationBehavior.JsonEncoder) + "\"]", json);
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
        private const string Pkcs8PemECPrivateKeyExplanatoryText = @"
Subject: CN=Atlantis
Issuer: CN=Atlantis
Validity: from 7/9/2012 3:10:38 AM UTC to 7/9/2013 3:10:37 AM UTC
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcKEsLbFoRe1W/2jP
whpHKz8E19aFG/Y0ny19WzRSs4qhRANCAASBAezkdGSm6tcM9ppuK9PYhpGjJi0i
y6T3Y16v8maAqNihK6YdWZI19n2ctNWPF4PTykPnjwpauqYkB5k2wMOp
-----END PRIVATE KEY-----this was a key.";
        private const string Pkcs1PemECPrivateKeyExplanatoryText = @"
Subject: CN=Atlantis
Issuer: CN=Atlantis
Validity: from 7/9/2012 3:10:38 AM UTC to 7/9/2013 3:10:37 AM UTC
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHChLC2xaEXtVv9oz8IaRys/BNfWhRv2NJ8tfVs0UrOKoAoGCCqGSM49
AwEHoUQDQgAEgQHs5HRkpurXDPaabivT2IaRoyYtIsuk92Ner/JmgKjYoSumHVmS
NfZ9nLTVjxeD08pD548KWrqmJAeZNsDDqQ==
-----END EC PRIVATE KEY-----this was a key.";
        private const string Pkcs8PemECPublicKeyExplanatoryText = @"
Subject: CN=Atlantis
Issuer: CN=Atlantis
Validity: from 7/9/2012 3:10:38 AM UTC to 7/9/2013 3:10:37 AM UTC
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgQHs5HRkpurXDPaabivT2IaRoyYt
Isuk92Ner/JmgKjYoSumHVmSNfZ9nLTVjxeD08pD548KWrqmJAeZNsDDqQ==
-----END PUBLIC KEY-----this was a key.";

        [Theory]
        [InlineData(Pkcs1PemECPrivateKey)]
        [InlineData(Pkcs8PemECPrivateKey)]
        [InlineData(Pkcs1PemECPrivateKeyExplanatoryText)]
        [InlineData(Pkcs8PemECPrivateKeyExplanatoryText)]
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
        [InlineData(Pkcs8PemECPublicKeyExplanatoryText)]
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

        private static ECJwk PrivateEcc256Key => ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        );

        private static ECJwk PublicEcc256Key => ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P256,
            x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        );

        private static ECJwk PrivateEcc256KKey = ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.Secp256k1,
            x: "6_H-LRU19Rzm4KCJNmzeCGoHPrm1CSBgOp-Npbdjaw0",
            y: "tp7FPpiX9sAMyGr72y27afvfZxmlANjyRut9StOq9xk",
            d: "Lra8VqtHiyayZ371elNxSJQg4OrWO0dLvMLiDfIRfc0"
        );

        private static ECJwk PublicEcc256KKey = ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.Secp256k1,
            x: "6_H-LRU19Rzm4KCJNmzeCGoHPrm1CSBgOp-Npbdjaw0",
            y: "tp7FPpiX9sAMyGr72y27afvfZxmlANjyRut9StOq9xk"
        );

        private static ECJwk PublicEcc384Key => ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P384,
            d: "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            x: "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            y: "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        );

        private static ECJwk PrivateEcc384Key => ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P384,
            d: "Wf9qS_1idTtZ13HKUMkNDFPacwsfduJxayYtLlDGYzp8la9YajkWTPQwZT0X-vjq",
            x: "2ius4b5QcXto95wPhpQsX3IGAtnT9mNjMvds18_AgU3wNpOkppfuT6wu-y-fnsVU",
            y: "3HPDrLpplnCJc3ksMBVD9rGFcAld3-c74CIk4ZNleOBnGeAkRZv4wJ4z_btwx_PL"
        );

        private static ECJwk PrivateEcc521Key => ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P521,
            d: "Adri8PbGJBWN5upp_67cKF8E0ADCF-w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HISTMh_RSmFFhTfBH",
            x: "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            y: "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        );

        private static ECJwk PublicEcc521Key => ECJwk.FromBase64Url
        (
            crv: EllipticalCurve.P521,
            x: "AEeo_Y06znu6MVjyvJW2_SX_JKK2DxbxF3QjAqkZhMTvwgLc3Z073vFwwiCHKcOwK2b5H8H4a7PDN6DGJ6YJjpN0",
            y: "AEESIwzgMrpPh9p_eq2EuIMUCCTPzaQK_DtXFwjOWsanjacwu1DZ3XSwbkiHvjQLrXDfdP7xZ-iAXQ1lGZqsud8y"
        );
    }
}
#endif