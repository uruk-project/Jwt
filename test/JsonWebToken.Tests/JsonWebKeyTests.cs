using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebKeyTests
    {
        [Fact]
        public void GetKeys_Empty_Default()
        {
            var jwks = new Jwks();
            var noKeys = jwks.GetKeys(default);

            Assert.Empty(noKeys);
        }

        [Fact]
        public void GetKeys_Full_Default()
        {
            var jwks = new Jwks
            {
                SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256, computeThumbprint: false),
                SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256, computeThumbprint: false),
                SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256, computeThumbprint: false),
                SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256, computeThumbprint: true),
            };
            var allKeys = jwks.GetKeys(default);

            Assert.Equal(4, allKeys.Length);
        }

        [Theory]
        [MemberData(nameof(GetJsonKeys))]
        public void CreateFromJson(string json, JsonEncodedText kid, JsonEncodedText alg)
        {
            var jwk = Jwk.FromJson(json);

            Assert.Equal(jwk.Kid, kid);
            if (!(jwk.Alg.EncodedUtf8Bytes.IsEmpty))
            {
                Assert.Equal(jwk.Alg, alg);
            }
        }

        [Theory]
        [MemberData(nameof(GetCertificates))]
        public void CreateFromCertificate(X509Certificate2 certificate, bool hasPrivateKey, int keySize)
        {
            var jwk = Jwk.FromX509Certificate(certificate, hasPrivateKey);

            Assert.Equal(keySize, jwk.KeySizeInBits);
            Assert.Equal(hasPrivateKey, jwk.HasPrivateKey);

            jwk = Jwk.FromX509Certificate(certificate, SignatureAlgorithm.RS256, hasPrivateKey);
            Assert.Equal(SignatureAlgorithm.RS256, jwk.SignatureAlgorithm);
            jwk = Jwk.FromX509Certificate(certificate, KeyManagementAlgorithm.RsaOaep, hasPrivateKey);
            Assert.Equal(KeyManagementAlgorithm.RsaOaep, jwk.KeyManagementAlgorithm);

            bool parsed;
            AsymmetricJwk key;
            if (hasPrivateKey)
            {
                parsed = Jwk.TryReadPrivateKeyFromX509Certificate(certificate, out key);
            }
            else
            {
                parsed = Jwk.TryReadPublicKeyFromX509Certificate(certificate, out key);
            }

            Assert.True(parsed);
            Assert.NotNull(key);
        }

        [Fact]
        public void CreateFromCertificate_Error()
        {
            Assert.Throws<ArgumentNullException>(() => Jwk.FromX509Certificate(null, withPrivateKey: true));
            Assert.Throws<InvalidOperationException>(() => Jwk.FromX509Certificate(Dsa1024Pfx_RC2ContentEncryption, withPrivateKey: true));
            Assert.Throws<InvalidOperationException>(() => Jwk.FromX509Certificate(Dsa1024Pfx_RC2ContentEncryption, withPrivateKey: false));

            Assert.Throws<ArgumentNullException>(() => Jwk.TryReadPrivateKeyFromX509Certificate(null, out _));
            Assert.Throws<ArgumentNullException>(() => Jwk.TryReadPublicKeyFromX509Certificate(null, out _));
            bool parsed = Jwk.TryReadPrivateKeyFromX509Certificate(Dsa1024Pfx_RC2ContentEncryption, out var key);
            Assert.False(parsed);
            Assert.Null(key);
            parsed = Jwk.TryReadPublicKeyFromX509Certificate(Dsa1024Pfx_RC2ContentEncryption, out key);
            Assert.False(parsed);
            Assert.Null(key);
        }

        public static IEnumerable<object[]> GetJsonKeys()
        {
            var fixture = new KeyFixture();
            foreach (var key in fixture.Jwks)
            {
                yield return new object[] { key.ToString(), key.Kid, key.Alg };
            }
        }

        public static IEnumerable<object[]> GetCertificates()
        {
            return Certificates;
        }

        [Fact]
        public void Thumbprint()
        {
            // https://tools.ietf.org/html/rfc7638#section-3.1
            var key = RsaJwk.FromBase64Url
            (
                e: "AQAB",
                n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                alg: SignatureAlgorithm.RS256
            );
            Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", key.Kid.ToString());
            key.Kid = JsonEncodedText.Encode("2011-04-29");

            var thumbprint = key.ComputeThumbprint();

            Assert.Equal(Encoding.UTF8.GetBytes("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"), thumbprint);
        }


        [InlineData("Basic 'oct' key", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Basic 'RSA' public key", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw""
}")]
#if SUPPORT_ELLIPTIC_CURVE
        [InlineData("Basic 'EC' public key", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Basic 'EC' private key", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Complete", @"
{
    ""alg"": ""ES256"",
    ""crv"": ""P-256"",
    ""kid"": ""0C0029DE-B898-4EFC-8586-DD4AA948AE22"",
    ""kty"": ""EC"",
    ""use"": ""sig"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
#endif
        [InlineData("Basic 'RSA' private key", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("With valid 'use'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("With valid 'key_ops'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""key_ops"": [""sign""]
}")]
        [InlineData("With valid 'key_ops' and 'use'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""key_ops"": [""sign""],
    ""use"": ""sig""
}")]
        [InlineData("With valid 'key_ops' and 'use' for encryption", @"
{
    ""alg"": ""RSA-OAEP"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-encryption-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""key_ops"": [""encrypt""],
    ""use"": ""enc""
}")]
        [InlineData("x5c, x5t & x5u", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""x5c"": [""b64/""],
    ""x5t"": ""qUqP5cyxm6YcTAhz05Hph5gvu9M"",
    ""x5t#S256"": ""n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"",
    ""x5u"": ""https://example.com""
}")]
        [Theory]
        public void Validate_Valid_DoesNotThrowException(string description, string json)
        {
            Jwk.Validate(json);
            Assert.True(true, description);

            var jwk = Jwk.FromJson(json);
            jwk.Validate();
            Assert.True(true, description);
        }

#if SUPPORT_ELLIPTIC_CURVE
        [InlineData("Missing 'x' for EC key", @"
{
    ""alg"": ""ES256"",
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Missing 'y' for EC key", @"
{
    ""alg"": ""ES256"",
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I""
}")]
        [InlineData("Incorrect signature algorithm for EC key", @"
{
    ""alg"": ""HS256"",
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect KM algorithm for EC key", @"
{
    ""alg"": ""RSA-OAEP"",
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect 'EC' key size", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HIw9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect 'EC' key size", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-521"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HIw9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
#endif
        [InlineData("Incorrect signature algorithm for RSA key", @"
{
    ""alg"": ""HS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("Incorrect KM algorithm for RSA key", @"
{
    ""alg"": ""DIR"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""enc""
}")]
        [InlineData("Incorrect signature algorithm for oct key", @"
{
    ""alg"": ""RS256"",
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect signature algorithm for oct key", @"
{
    ""alg"": ""RSA-OAEP"",
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect signature algorithm", @"
{
    ""alg"": ""RS255"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("Inconsistent signature algorithm & 'use'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""enc""
}")]
        [InlineData("Inconsistent encryption algorithm & 'use'", @"
{
    ""alg"": ""RSA-OAEP"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("Incorrect key management algorithm", @"
{
    ""alg"": ""A256KW"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("Inconsistent key_ops and use 'sig'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig"",
    ""key_ops"": [""sign"", ""encrypt""]
}")]
        [InlineData("Inconsistent key_ops and use 'enc'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""enc"",
    ""key_ops"": [""encrypt"", ""sign""]
}")]
        [InlineData("Invalid key_ops", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig"",
    ""key_ops"": [""X""]
}")]
        [InlineData("Invalid 'use'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""X""
}")]
        [InlineData("Missing RSA 'e' type", @"
{
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'n' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'd' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'p' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'q' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'dp' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'dq' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'qi' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU""
}")]
        [InlineData("Invalid 'key_ops' value", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""key_ops"": [""sign"", ""X""]
}")]
        [InlineData("Inconsistent 'key_ops' with signing 'alg'", @"
{
    ""kty"": ""oct"",
    ""alg"": ""A128KW"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""key_ops"": [""sign""]
}")]
        [InlineData("Inconsistent 'key_ops' with encryption 'alg'", @"
{
    ""kty"": ""oct"",
    ""alg"": ""HS256"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""key_ops"": [""encrypt""]
}")]
        [InlineData("'RSA' with invalid key size", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOwOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("'RSA' with private key invalid", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQVFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("'RSA' with 'p' invalid size", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""AQAB"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("invalid x5t", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""x5c"": [""b64/""],
    ""x5t"": ""n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"",
    ""x5t#S256"": ""n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"",
    ""x5u"": ""https://example.com""
}")]
        [InlineData("invalid xt#S256c", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""x5c"": [""b64/""],
    ""x5t"": ""qUqP5cyxm6YcTAhz05Hph5gvu9M"",
    ""x5t#S256"": ""qUqP5cyxm6YcTAhz05Hph5gvu9M"",
    ""x5u"": ""https://example.com""
}")]
        [Theory]
        public void Validate_Invalid_ThrowsJwkCheckException(string description, string json)
        {
            Assert.ThrowsAny<JwkValidationException>(() => Jwk.Validate(json));
            Assert.True(true, description);

            var jwk = Jwk.FromJson(json);
            Assert.ThrowsAny<JwkValidationException>(() => jwk.Validate());
            Assert.True(true, description);
        }

        [InlineData("Basic 'oct' key", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Basic 'RSA' public key", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw""
}")]
#if SUPPORT_ELLIPTIC_CURVE
        [InlineData("Basic 'EC' public key", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Basic 'EC' private key", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Complete", @"
{
    ""alg"": ""ES256"",
    ""crv"": ""P-256"",
    ""kid"": ""0C0029DE-B898-4EFC-8586-DD4AA948AE22"",
    ""kty"": ""EC"",
    ""use"": ""sig"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
#endif
        [InlineData("Basic 'RSA' private key", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("With valid 'use'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("With valid 'key_ops'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""key_ops"": [""sign""]
}")]
        [InlineData("With valid 'key_ops' and 'use'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""key_ops"": [""sign""],
    ""use"": ""sig""
}")]
        [InlineData("With valid 'key_ops' and 'use' for encryption", @"
{
    ""alg"": ""RSA-OAEP"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-encryption-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""key_ops"": [""encrypt""],
    ""use"": ""enc""
}")]
        [InlineData("x5c, x5t & x5u", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""x5c"": [""b64/""],
    ""x5t"": ""qUqP5cyxm6YcTAhz05Hph5gvu9M"",
    ""x5t#S256"": ""n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"",
    ""x5u"": ""https://example.com""
}")]
        [Theory]
        public void Check_Valid(string description, string json)
        {
            Jwk.Validate(json);
            Assert.True(true, description);
        }

        [InlineData("Empty string", @"")]
        [InlineData("Empty JSON object", @"{}")]
        [InlineData("Malformed JSON object", @"
{
   ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw""
")]
        [InlineData("Missing kty", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw""
}")]
        [InlineData("Invalid kty", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""XXX"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw""
}")]
        [InlineData("Invalid use", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""oct"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""X""
}")]
        [InlineData("Incorrect signature algorithm for RSA key", @"
{
    ""alg"": ""HS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("Incorrect signature algorithm for EC key", @"
{
    ""alg"": ""HS256"",
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": true
}")]
        [InlineData("Incorrect signature algorithm for oct key", @"
{
    ""alg"": ""RS256"",
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect signature algorithm", @"
{
    ""alg"": ""RS255"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("Inconsistent signature algorithm & 'use'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""enc""
}")]
        [InlineData("Inconsistent encryption algorithm & 'use'", @"
{
    ""alg"": ""RSA-OAEP"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("Incorrect key management algorithm", @"
{
    ""alg"": ""A256KW"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("Inconsistent key_ops and use 'sig'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig"",
    ""key_ops"": [""sign"", ""encrypt""]
}")]
        [InlineData("Inconsistent key_ops and use 'enc'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""enc"",
    ""key_ops"": [""encrypt"", ""sign""]
}")]
        [InlineData("Invalid key_ops", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig"",
    ""key_ops"": [""X""]
}")]
        [InlineData("Invalid 'use'", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""X""
}")]
        [InlineData("Missing optionnal rsa parameter", @"
{
    ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""kty"": ""XXX"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""
}")]
        [InlineData("Incorrect kty type", @"
{
    ""kty"": true,
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
#if SUPPORT_ELLIPTIC_CURVE
        [InlineData("Incorrect crv type", @"
{
    ""kty"": ""EC"",
    ""crv"": true,
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect EC 'd' type", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": true,
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect EC 'x' type", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": true,
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect EC 'y' type", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": true
}")]
        [InlineData("Incorrect EC 'crv' type", @"
{
    ""kty"": ""EC"",
    ""crv"": ""X"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I""
}")]
#endif
        [InlineData("Incorrect RSA 'e' type", @"
{
    ""e"": true,
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Incorrect RSA 'n' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": true,
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Incorrect RSA 'd' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": true,
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        //        [InlineData("Incorrect RSA 'y' type", @"
        //{
        //    ""e"": ""AQAB"",
        //    ""kty"": ""RSA"",
        //    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw""
        //    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
        //    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
        //    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
        //    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
        //    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
        //    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
        //}")]    
        [InlineData("Incorrect RSA 'p' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": true,
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Incorrect RSA 'q' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": true,
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Incorrect RSA 'dp' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": true,
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Incorrect RSA 'qi' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": true
}")]
        [InlineData("Incorrect RSA 'dq' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": true,
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'e' type", @"
{
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'n' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'd' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'p' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'q' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'dp' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'dq' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("Missing RSA 'qi' type", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU""
}")]

        [InlineData("Non base64url encoding", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSi%Mk0""
}")]
        [InlineData("Non ASCII encoding", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk"",
    ""x5t"": ""/+😀Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk""
}")]
        [InlineData("Non base64url encoding with non ASCII char", @"
{
    ""kty"": ""oct"",
    ""key_ops"": ""X"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSi€Mk0""
}")]
        [InlineData("Invalid 'key_ops' type", @"
{
    ""kty"": ""oct"",
    ""key_ops"": ""sign"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Invalid 'key_ops' value", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""key_ops"": [""sign"", ""X""]
}")]
        [InlineData("Incorrect 'EC' key size", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-256"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HIw9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("Incorrect 'EC' key size", @"
{
    ""kty"": ""EC"",
    ""crv"": ""P-521"",
    ""d"": ""w9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HIw9WpI4vAnoE9iZsnRTZI9D20Ji9rzLyyEPp8KriI_HI"",
    ""x"": ""cRs59CHa39w6m48qqhqygXNXLmAbfp8yteQTjGBie9I"",
    ""y"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [InlineData("'RSA' with invalid key size", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOwOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("'RSA' with private key invalid", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQVFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("'RSA' with 'p' invalid sized", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sMsM"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [InlineData("invalid x5c value", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""x5c"": [""####""],
    ""x5t"": ""qUqP5cyxm6YcTAhz05Hph5gvu9M"",
    ""x5t#S256"": ""n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"",
    ""x5u"": ""https://example.com""
}")]
        [InlineData("invalid x5c type", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""x5c"": [true],
    ""x5t"": ""qUqP5cyxm6YcTAhz05Hph5gvu9M"",
    ""x5t#S256"": ""n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"",
    ""x5u"": ""https://example.com""
}")]
        [InlineData("invalid x5t", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""x5c"": [""b64/""],
    ""x5t"": ""qUqP5cyxm6YcTAhz05Hph5gvu"",
    ""x5t#S256"": ""n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"",
    ""x5u"": ""https://example.com""
}")]
        [InlineData("invalid xt#S256c", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""x5c"": [""b64/""],
    ""x5t"": ""qUqP5cyxm6YcTAhz05Hph5gvu9M"",
    ""x5t#S256"": ""n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgggg"",
    ""x5u"": ""https://example.com""
}")]
        [InlineData("invalid x5u", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""x5c"": [""b64/""],
    ""x5t"": ""qUqP5cyxm6YcTAhz05Hph5gvu9M"",
    ""x5t#S256"": ""n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"",
    ""x5u"": false
}")]
        [InlineData("invalid 'key_ops' type", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""key_ops"": [true]
}")]
        [InlineData("inconsistent 'key_ops' with signature 'alg'", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""key_ops"": [""encrypt""],
    ""alg"": ""HS256""
}")]
        [InlineData("inconsistent 'key_ops' with KM 'alg'", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0"",
    ""key_ops"": [""sign""],
    ""alg"": ""A128KW""
}")]
        [InlineData("Invalid B64 value", @"
{
    ""e"": ""AQAB"",
    ""kty"": ""RSA"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""d"": ""VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"",
    ""p"": ""*KlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""q"": ""uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"",
    ""dp"": ""w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"",
    ""dq"": ""o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"",
    ""qi"": ""eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo""
}")]
        [Theory]
        public void Check_Invalid(string description, string json)
        {
            Assert.ThrowsAny<JwkValidationException>(() => Jwk.Validate(json));
            Assert.True(true, description);
        }

        public static IEnumerable<object[]> Certificates
        {
            get
            {
                yield return new object[] { CertSha256_1024, true, 1024 };
                yield return new object[] { CertSha256_1024_Public, false, 1024 };
                yield return new object[] { CertSha256_2048, true, 2048 };
                yield return new object[] { CertSha256_2048_Public, false, 2048 };
                yield return new object[] { CertSha384_2048, true, 2048 };
                yield return new object[] { CertSha384_2048_Public, false, 2048 };
                yield return new object[] { CertSha512_2048, true, 2048 };
                yield return new object[] { CertSha512_2048_Public, false, 2048 };
            }
        }

        private const string CertPassword = "abcd";

        private static readonly string Sha256_1024 = @"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";
        private static readonly string Sha256_1024_Public = "MIICWTCCAcKgAwIBAgIQPq8RWqoOL51G/qUxq7tBizANBgkqhkiG9w0BAQsFADA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAxADAAMgA0AF8AUwBIAEEAMgA1ADYwHhcNMTQxMjI2MTUyNzAwWhcNMzkxMjMxMjM1OTU5WjA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAxADAAMgA0AF8AUwBIAEEAMgA1ADYwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMl0ubbO3e3FpeMN2/gjz0YElurF0UCT25777CmNfzpvxtuvziUxa/ALMxmz+sVLzKb6kMuLNagU12cYZS3ksgntqxz8R/VyZO33hysNAMeMcdeOMhMm6ubTXEqqdHAb4TUPhme6o7Bvpcx3yPlxECoy6XE5A0VlYBgWzqMJN6F5AgMBAAGjajBoMGYGA1UdAQRfMF2AEKiIeaB2ShCC/Mrhyxg2Lf+hNzA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAxADAAMgA0AF8AUwBIAEEAMgA1ADaCED6vEVqqDi+dRv6lMau7QYswDQYJKoZIhvcNAQELBQADgYEAaqChtfN/l6xTcMItwFG9jhDPuWeLDXAplM0vSwbia1fIaAXdcFRSaH+5QwqoQSDROcfiWRbPNWhFXfzOj7FEBmtbGifiqDvHislRHYrqnz9FRKiay0KYn0tJ2RUsTlKxZNz0WVu9M05wJjYH4TB04ad5FhgxJZ2h/y1X+An4a/o=";
        private static readonly X509Certificate2 CertSha256_1024 = new X509Certificate2(Convert.FromBase64String(Sha256_1024), "SelfSigned1024_SHA256", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        private static readonly X509Certificate2 CertSha256_1024_Public = new X509Certificate2(Convert.FromBase64String(Sha256_1024_Public), "SelfSigned1024_SHA256");

        private static readonly string Sha256_2048 = @"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";
        private static readonly string Sha256_2048_Public = @"MIIDXjCCAkagAwIBAgIQY9+BvEWchJpAX/tDKzHwFDANBgkqhkiG9w0BAQsFADA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAyADAANAA4AF8AUwBIAEEAMgA1ADYwHhcNMTQxMjI2MTUyNzM2WhcNMzkxMjMxMjM1OTU5WjA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAyADAANAA4AF8AUwBIAEEAMgA1ADYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWE7VB3zRniE3CsYLy9sCLAdFB7AsGKMkZsJxiwKD1uv+OKshPN9Epm7ZJQWjm6YGeQYKGQUaNs5Z1NaapKLaT52jqcTLRbOC5g331GkXTPICkjDHsR+NPyd7J4O4Hl2ls8q1+mcYhHSJOoamWOGZqtpCfpqqOhHhG75Rn282kA90Ybc6xY+rTgBIYgSt+/l3/muI3XTU6wghifYwZfID1IngBEb+MD346QgpiJcWObL+WIXPGpLNmDjwJZ8IlXvgO5JPSz1wxCyb8EJHUp4hQUc778RtKB82UXbckhL3eW49v1jpuJoqeNm924vlMX3IYAwYDBF93K6F8yu2otpwvAgMBAAGjajBoMGYGA1UdAQRfMF2AEM2V/dQqCNOhP9VPwFcAubuhNzA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAyADAANAA4AF8AUwBIAEEAMgA1ADaCEGPfgbxFnISaQF/7Qysx8BQwDQYJKoZIhvcNAQELBQADggEBAKSksE7/5TOc5ngnD54poNnaPWrw4kolFzqYdw1/s/evScT4tgFYR1FrmPB50KYoZ0c8FzDY7PK4SkB7x7xFbjPYZwcEzeHqZ+WsHO3UxI2nU94CUsBmNR09CMMIwt/1A1yfzSNTJE452YtycdLVJUC6NBR30Di5YOFWPwIEO5XE0J7Os1xuhZc6AEKy2STp0I3FL27gHu3R+3Xhqru6fQIOw52Pcp1axXsuE9cQ/HKyeNTvM02FZmjlx/Vy3lC5I/2xiUJrhqzczOMRRB8clpsAp2uNWfrzJ0aLCprQO62pN9L/51PWbSMsNfnfuUo4eZHv2noQ3mGzJPXyK43Omn0=";
        private static readonly X509Certificate2 CertSha256_2048 = new X509Certificate2(Convert.FromBase64String(Sha256_2048), "SelfSigned2048_SHA256", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        private static readonly X509Certificate2 CertSha256_2048_Public = new X509Certificate2(Convert.FromBase64String(Sha256_2048_Public), "SelfSigned2048_SHA256");

        private static readonly string Sha384_2048 = @"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";
        public static readonly string Sha384_2048_Public = "MIIDXjCCAkagAwIBAgIQmT68AQ3vPa9NmlShoEZVVjANBgkqhkiG9w0BAQwFADA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAyADAANAA4AF8AUwBIAEEAMwA4ADQwHhcNMTQxMjI2MTUyODExWhcNMzkxMjMxMjM1OTU5WjA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAyADAANAA4AF8AUwBIAEEAMwA4ADQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdtHnoaSiqQy+hBEmLnxgOy2euwvtpC0CHnzIJILsoyBdGELQ8cuPCTKT1JNBluphBtFF3oB3xoxRJWrAzNgvDqm09yS57rFXbV9jK9j8zP/QdEr9j4i1CckwNVY4PNCerF3bDpRDD00IHD+NObLLcaadFBjlzMxRjqd4D8ko8Jxl0g+gO15QwlXNQW83H058Qcd20chiifr1nILcJKEdV25fhfPIqvQny39zaydEDMnfAGo7Puj6ODjYbjZ50U8mUhtYdVtye8tP7g2C8lhwUT4N2B+sJCbInApT3ONTa9clPT23Fif/2JsNMRISt5bnDJpBCtP29l0i2Z7+5PUnfAgMBAAGjajBoMGYGA1UdAQRfMF2AEGd1geu132c0YEEInmdrMdehNzA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAyADAANAA4AF8AUwBIAEEAMwA4ADSCEJk+vAEN7z2vTZpUoaBGVVYwDQYJKoZIhvcNAQEMBQADggEBAGrxk6od8vgHb/tRoFgGcGfubMlZMRvH2Ly+4cdLpgIYKqvEWTnze0KVrd/y7qyoJc3pbAqs3XRrhAFiB6NACP5PeOFV+WvA2PF45qSO7kXwACXlYqvHQcnEo33BWfLiBpKY2zXUZzUOyZAOpNYM8SDLNH4wj0PH8F4pU18i6Q/E2t5cVUR11PpHCpKoUlMNClx8sCW4/Pamvn3BQw+NyrMpCz9NmeY5k46h8smPB2Z8hflLUc9zcJ8fv+dvun87bLa0S8Y3pM/gMrbVswsfkQ4uZY6iAKN4hGQw+SLb8KG8vYRGI726S8h99el0kRJBLZv7JD6oBbUI+92s2KN7I7A=";
        private static readonly X509Certificate2 CertSha384_2048 = new X509Certificate2(Convert.FromBase64String(Sha384_2048), "SelfSigned2048_SHA384", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        private static readonly X509Certificate2 CertSha384_2048_Public = new X509Certificate2(Convert.FromBase64String(Sha384_2048_Public), "SelfSigned2048_SHA384");

        private static readonly string Sha512_2048 = @"MIIKXwIBAzCCCh8GCSqGSIb3DQEHAaCCChAEggoMMIIKCDCCBgkGCSqGSIb3DQEHAaCCBfoEggX2MIIF8jCCBe4GCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvcNAQwBAzAOBAj5j6Q6YCZ3pgICB9AEggTYMipPiUmsOaVV/nfJ8XtkdY3OcLyfMBYVPxur3NuPre10EZq3NkxsxbigO/kPcKJPEjZ/ekb7/h6jEPQRFNXTHVpJCxcc3JdPl0PniitQGUgFIPCgtL60GG0XjcDQPPkOwPOicYIysNu7WO3maQ3FTuht6gO0VQKKTZTBjysmWO1QrKts66vKMAFZ7zlJcBa8kk8BNkAgzRYfwaZHEOhmTi3clR5FdgZbbhlJfHDNOCVOqbHDWJ6rr5PW5brJpIKhinbfIrfya+osqM8EGcIrt3TdC4/aIte/ALigcc4+zXdwcAYTzNIm4mLLKsbm/bAR5twubXmo9qbtgO2lD23uPJ8Rf5K7JSwjbgxCWSjzWoLyTBYdTQBGtlbux2K4M7iqlf+SWGkjexlgMZLFXPljroRyXq/qdj/zGeIln0Ec0WS2Mdq5a8uzxCIqaOH1GMw61YjJbUlRtA0ZguG7oLuI8cDDuIKhxBpgbyXG9hkyPAsNlPQLqPvl8H40DQVqlw8B2QS9Q0Io8WexE6YnhuutPS14tn7a6UbUqNI8MUzjYX6lKG5R8pmUjdk8gMN2g9cY5JVEzLe+AtoYrpX+69+Z52uUFXRVvB5CltdFtpupX9ZZzoAO+9QPx3xSC6D0bbeCfTa8mJ8H4rDRYzDdMyObmBKevHFPsOUrUY6An0Vu6dBrgAG3z4EjFP83o2LJnQzRb+zbrF9w5Kc8qIDY/7HFcDD85YgMyn1IiQr3RqP6Puen/HQNvjXJxy2+M2etRkRLCIyRhJf/4gLm8YbKR+7kMWGy/BBjIZ/8pc0JNe71bpjwtT3ngQ+Zw7hoKoZ4DxfkowXfqAFoaPWx8hbVBpc2mrg2YYF4DE7JlQId72UXAOgUiQzyWZ5TepXrzbjude8FXAIhEJA/nz9jvSf0zWyHbMS0iHfsKsREnCu9u4RgX3tuQL3TyT6HOHNOpCFbHB9nBYgM4k1BkcJGaUGeCm2P1zxE4J/CQ41vw4J5w8oTccMzIYQZEXhHnGmd2x54B4nTWVGWlWb5hg0cqvapvgrACfNjHyV6SMQRBtrxlw5mVTtY3It+w3Xn64PVOt2A4cLSYyTWNQ5m9cdI8/QTmfNk7VEvAUFJ50B/SZYKKQi/Inbq014G8caB7amr6IFf8GphS1dgGOIc8qnSSmSK5c7xpcAGtafdPWl9mTK7ZWRG6ClsEHWo5YpViRtZdJkohk5EKajKeR0enwI3v7oyGqkOfKEk0BlDc3zhCpOSspbBr08SRxUzGtGmMOHmNAMWJ6ay8AEJ0gRyj6saJ1MIzjW70M4o/9x3kHo3BiWqVVaDtxpyOObJxx1ze26d/G/9HCuf3nuM8m9TikngHsQl+zT6Bvb08ChVRjAT6sDzbvB/FGiKyux7wX0wCqkTHmfYOqWeJyCHDndgFhpt3J+HX//OMunmkpEXBdq4afqL5h4nzqyIfwL5VtXN3kW5muvMLZjOkM1xQd1bZgO3iZzOPwXOvWITlcG5OTJWEjHE+bD7uq9FvjdiWrGx26Ym9oEqef8zdBddGHyFlZ1SCtg371LyvsUUkm0TVUGdOrm3Ii56g/FhU8vtsUtY1m19hZYAPkMBT2LfUwddL62sZqY3RMJOpa98BSfi2N+AJiiKOLLWOzeldsGBixYOBjGB3DANBgkrBgEEAYI3EQIxADATBgkqhkiG9w0BCRUxBgQEAQAAADBXBgkqhkiG9w0BCRQxSh5IADkANQA1AGUANgAyAGYANgAtADkAMQA1ADAALQA0AGMAMgBjAC0AOQAzAGIANwAtAGEAYwBjADMAOAA5ADIAOAAyADkAZgAxMF0GCSsGAQQBgjcRATFQHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAHQAcgBvAG4AZwAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIwggP3BgkqhkiG9w0BBwagggPoMIID5AIBADCCA90GCSqGSIb3DQEHATAcBgoqhkiG9w0BDAEGMA4ECGY+WNOUhlCtAgIH0ICCA7DoQ3i+xoibf75j7DQek7tg7MrlhV2R9+urbPhMKyoUodhmNOT7HAwx21tBwTw7i81G+fPQ+1qJB0JcRvRryXqXo9n1PlWhT+5zDM+7e+3NBKhA+obJUCqNwtbO8le6wauodpphMPT6/btVi6ehAbhXCPl4Ul3nbzzquEOQA1ynpBjfCJdNc9FWGuDwyDEWuxu/TX0y17GJmBDCjzqEaE7yFV0RBjtRhlCNWHXdj72oxLOftG8ibO/4V2QuLls//9Y165gIgMkEnmJ723NI7Nems3CVuB1TvzAb2Pv6wd7bL6rsmujviWP0BzqjNP1+KMheJ5JiUYKEBE3xQlPNq+CaqaznIM2A9EBnJoTHOPsVqn+wlXfIwnERpq7+toJmSDlfwiexIWXZ6BSoU6BJDEU1NOGMwHOyv3+NwQonXgPbx7aU4z15tTj5R7bHyaNJR+5ad5ApCcESzISYCgx+lnllgdkOVN1IA8SVioUkkV7TpWMKi7KvB9tNp2+8zpcQQ5XDSUGUmVZP4ouLY+QUUMtFZ39cB2+jSF72ZlY7QWBTKwg1UWhZcLYYSIe5VdagxUauf1bYvKvPlCCIXfHrqzta0rH93HMryyKcPlIvpr3X2jr9BzDhbaCp/flqeDLJoH0SMNinMI1oq4Eh5HotVrq81mSRmaBE+fnr1gpVPKUNw4Yj/tG5TRgycSauB7gmYgetZwRxL1PrjA5R2ZuFBdq1JnOMwLDgqj0mroaK+r2XjVkK16AlbFjvaEBQtFB4n166ignG6s5T4OCcBnWa8PJJU8kFu2nLPGlJGPtiGYpXyfJjuMkCD/VCfSj5F1VD24Aw256IY6dCig2tNO/31CmW7+Q0ZlX/y15uuN+zQp7iZQvH3+cyhQkMap0r/7i0Wge+uFpRLQmsZba1pIksJ6fcD3cCyuyXdV2LflBsSCRBqohHgbrk9Pzcb/7t1C6oONLM7saAw6gosoxTPTKagZzb4guHVdKyNTVnKSI8FVDdP4C7MGp4kqPbaVEKvYXbvAnjpRqcWLQMLhqoxxeMoLRflcR3wabGuj3jbu5ANXfIuCkenSkfQYymqXF0d5mo3l4Ak0Wv/nAnx6t9wr5ZMI4+OpXgAHUCZ0kTs924hxRQglpi7i2lQUFrt/TAcp52DCPMst4YlhBP90JFXT/kEvUNLaKahqSKxLbrDHNgFZVVm5+foU0Cb9qKXxobTytIKMzqOUQ5JOERYnDvL2fgascWOfn9mkVuhfd+MpayBCQXrjA3MB8wBwYFKw4DAhoEFBNPLaPVF8m94SxtpthICain/6n7BBSIrBaNgWE4o5NiBKid9L1c9R1m8A==";
        private static readonly string Sha512_2048_Public = "MIIDXjCCAkagAwIBAgIQzTfvf7ABYLxKOErOiooMIjANBgkqhkiG9w0BAQ0FADA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAyADAANAA4AF8AUwBIAEEANQAxADIwHhcNMTQxMjI2MTUyODMxWhcNMzkxMjMxMjM1OTU5WjA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAyADAANAA4AF8AUwBIAEEANQAxADIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzk2XIZKwGbblamSyJ3l+Co+SzCqSV4X7COoJM0R7UwgYT12hD30xhvDUpQrhuHc2ecF5SPggpG/Z63BXsIaqSMCcmzOoV9igFDqWzecbj5Mz/xSm/ZjJ7HXxiklSekWFG1q/8crd1HfdHjaCm+hMxpfXFSH+h3bSxv+2XBkT+Y35wUXnnw6Q/rE+ieW5+xn0MUvh1UkFCl7+ZDOhIzbXkzM/BKUAPxbJBjXeAr0Cum/IVFStavxi21Sgj1XoMuW6tlFX+eG6wUvmh4LjVTlIVdrV8bqxDIm/w/vCwlyvcQxERlP3TVlusUkc157pXKvhqNlPdEGG9kUumMVaziNxNAgMBAAGjajBoMGYGA1UdAQRfMF2AEMQYtKMfx+sbsi5bQ7l/LTShNzA1MTMwMQYDVQQDHioAUwBlAGwAZgBTAGkAZwBuAGUAZAAyADAANAA4AF8AUwBIAEEANQAxADKCEM0373+wAWC8SjhKzoqKDCIwDQYJKoZIhvcNAQENBQADggEBAAvM9kCf8fpwiLYtEQK6ryHmg6MC5L2BNGsuRUOZNDkp+/LZF48tkfL6dTYslj3kPeEBGAA9ggIjDinTbPEveEpPUoZTllkMj9A9T963yhaLlsVAJDPbJw8XlHO+c01VjUtIjaVtIvJaCNoXF0S+TfbRDKceiEXYcDS+ySyssCi4x23nd2fylRvpiaOrFAMDXHF440vR/I18VEqKuPa/NWj/JbVdaXAmyjjtHi7GIcL6rQQFpbDDfrzKmNCc/SXLkNQ97ArngEkOzZhOmP2aZ7ZqdX/h3mRQ3wo91+WfVfFfbhKc4qTUQHr9rop2JeEhu8WaRwVoqz6PtXB6WtIX8hk=";
        private static readonly X509Certificate2 CertSha512_2048 = new X509Certificate2(Convert.FromBase64String(Sha512_2048), "SelfSigned2048_SHA512", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        private static readonly X509Certificate2 CertSha512_2048_Public = new X509Certificate2(Convert.FromBase64String(Sha512_2048_Public), "SelfSigned2048_SHA512");

        private static readonly X509Certificate2 Dsa1024Pfx_RC2ContentEncryption = new X509Certificate2(Convert.FromBase64String("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"), "1234");
    }
}
