using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebTokenWriterTests : IClassFixture<KeyFixture>, IClassFixture<TokenFixture>
    {
        private readonly KeyFixture _keys;
        private readonly TokenFixture _tokens;

        public JsonWebTokenWriterTests(KeyFixture keys, TokenFixture tokens)
        {
            _keys = keys;
            _tokens = tokens;
        }

        private readonly RsaJwk RsaKey = RsaJwk.FromBase64Url
        (
            n: "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            e: "AQAB",
            d: "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            p: "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
            q: "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
            dp: "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
            dq: "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
            qi: "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
            alg: KeyManagementAlgorithm.Rsa1_5
        );

        [Theory]
        [ClassData(typeof(DescriptorTestData))]
        public void Write_Valid(string token)
        {
            var descriptor = _tokens.Descriptors[token];
            JwtWriter writer = new JwtWriter();
            var value = writer.WriteToken(descriptor);

            var policy = new TokenValidationPolicyBuilder()
                .WithDecryptionKeys(_keys.Jwks)
                .IgnoreSignatureByDefault()
                .Build();

            var result = Jwt.TryParse(value, policy, out var jwt);
            Assert.True(result);

            if (!(descriptor is JwsDescriptor jwsPayload))
            {
                if (!(descriptor is JweDescriptor jwePayload))
                {
                    throw new Xunit.Sdk.IsNotTypeException(typeof(JwtDescriptor), descriptor);
                }

                jwsPayload = jwePayload.Payload;
            }

            Assert.NotNull(jwsPayload);
            if (jwsPayload.Payload.Count > 0)
            {
                Assert.True(jwt.Payload.TryGetClaim("iat", out var iat));
                Assert.True(jwt.Payload.TryGetClaim("exp", out var exp));
                Assert.True(jwt.Payload.TryGetClaim("iss", out var iss));
                Assert.True(jwt.Payload.TryGetClaim("aud", out var aud));
                Assert.True(jwt.Payload.TryGetClaim("jti", out var jti));
            }
        }

        [Fact]
        public void Write_RSAES_PKCS1_v1_5_and_AES_128_CBC_HMAC_SHA_256()
        {
            var plaintext = "Live long and prosper.";

            var descriptor = new PlaintextJweDescriptor(RsaKey, KeyManagementAlgorithm.Rsa1_5, EncryptionAlgorithm.A128CbcHS256);
            descriptor.Payload = plaintext;

            JwtWriter writer = new JwtWriter();
            var value = writer.WriteToken(descriptor);

            var policy = new TokenValidationPolicyBuilder()
                .WithDecryptionKey(RsaKey)
                .IgnoreSignatureByDefault()
                .Build();

            var result = Jwt.TryParse(value, policy, out var jwt);
            Assert.True(result);

            Assert.Equal(plaintext, jwt.Plaintext);
        }

        [Fact]
        public void Write_Utf8ToEscape()
        {
            var plaintext = "Live long and prosper!€";

            var descriptor = new PlaintextJweDescriptor(RsaKey, KeyManagementAlgorithm.Rsa1_5, EncryptionAlgorithm.A128CbcHS256);
            descriptor.Payload = plaintext;

            JwtWriter writer = new JwtWriter();
            var value = writer.WriteToken(descriptor);

            var policy = new TokenValidationPolicyBuilder()
                .WithDecryptionKey(RsaKey)
                .IgnoreSignatureByDefault()
                .Build();

            var result = Jwt.TryParse(value, policy, out var jwt);
            Assert.True(result);

            Assert.Equal(plaintext, jwt.Plaintext);
        }

        [Fact]
        public void Write_Binary()
        {
            var data = new byte[256];
            FillData(data);
            var key = RsaJwk.FromBase64Url
            (
                 n: "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
                 e: "AQAB",
                 d: "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
                 p: "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
                 q: "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
                 dp: "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
                 dq: "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
                 qi: "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
                 alg: KeyManagementAlgorithm.Rsa1_5
            );

            var descriptor = new BinaryJweDescriptor(key, KeyManagementAlgorithm.Rsa1_5, EncryptionAlgorithm.A128CbcHS256);
            descriptor.Payload = data;

            JwtWriter writer = new JwtWriter();
            var value = writer.WriteToken(descriptor);
            Assert.NotNull(value);

            var policy = new TokenValidationPolicyBuilder()
                .WithDecryptionKey(key)
                .IgnoreSignatureByDefault()
                .Build();

            var result = Jwt.TryParse(value, policy, out var jwt);
            Assert.True(result);

            Assert.True(jwt.RawValue.Span.SequenceEqual(data));
        }

        private static void FillData(byte[] data)
        {
#if NETSTANDARD2_0 || NETCOREAPP2_0 || NETFRAMEWORK
            using var rng = RandomNumberGenerator.Create();
            rng.GetNonZeroBytes(data);
#else
            RandomNumberGenerator.Fill(data);
#endif
        }

        [Fact]
        public void Write_Compressed()
        {
            var plaintext = "Live long and prosper.".PadRight(992 * 100, 'X');

            var descriptor = new PlaintextJweDescriptor(RsaKey, KeyManagementAlgorithm.Rsa1_5, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def);
            descriptor.Payload = plaintext;

            JwtWriter writer = new JwtWriter();
            var value = writer.WriteToken(descriptor);

            var policy = new TokenValidationPolicyBuilder()
                .WithDecryptionKey(RsaKey)
                .IgnoreSignatureByDefault()
                .Build();

            var result = Jwt.TryParse(value, policy, out var jwt);
            Assert.True(result);

            Assert.Equal(plaintext, jwt.Plaintext);
        }

        public class DescriptorTestData : IEnumerable<object[]>
        {
            private readonly TokenFixture _tokens;

            public DescriptorTestData()
            {
                _tokens = new TokenFixture();
            }

            public IEnumerator<object[]> GetEnumerator()
            {
                foreach (var item in _tokens.Descriptors)
                {
                    yield return new object[] { item.Key };
                }
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }

    }
}
