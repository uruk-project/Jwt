using JsonWebToken.Performance;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebTokenWriterTests
    {
        private readonly RsaJwk RsaKey = new RsaJwk
        {
            N = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            E = "AQAB",
            D = "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            P = "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
            Q = "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
            DP = "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
            DQ = "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
            QI = "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
            Alg = KeyManagementAlgorithm.RsaPkcs1.Name
        };

        [Theory]
        [MemberData(nameof(GetDescriptors))]
        public void Write_Valid(string token)
        {
            var descriptor = Tokens.Descriptors[token];
            JwtWriter writer = new JwtWriter();
            var value = writer.WriteToken(descriptor);

            var reader = new JwtReader(Keys.Jwks);
            var result = reader.TryReadToken(value, TokenValidationPolicy.NoValidation);
            Assert.Equal(TokenValidationStatus.Success, result.Status);

            var jwt = result.Token;

            var payload = descriptor as IJwtPayloadDescriptor;
            Assert.Equal(payload.IssuedAt, jwt.IssuedAt);
            Assert.Equal(payload.ExpirationTime, jwt.ExpirationTime);
            Assert.Equal(payload.Issuer, jwt.Issuer);
            Assert.Equal(payload.Audiences?.FirstOrDefault(), jwt.Audiences?.FirstOrDefault());
            Assert.Equal(payload.JwtId, jwt.Id);
        }

        [Fact]
        public void Write_RSAES_PKCS1_v1_5_and_AES_128_CBC_HMAC_SHA_256()
        {
            var plaintext = "Live long and prosper.";

            var descriptor = new PlaintextJweDescriptor(plaintext);
            descriptor.Key = RsaKey;
            descriptor.EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256;

            JwtWriter writer = new JwtWriter();
            var value = writer.WriteToken(descriptor);

            var reader = new JwtReader(RsaKey);
            var result = reader.TryReadToken(value, TokenValidationPolicy.NoValidation);
            Assert.Equal(TokenValidationStatus.Success, result.Status);

            var jwt = result.Token;

            Assert.Equal(plaintext, jwt.Plaintext);
        }

        [Fact]
        public void Write_Binary()
        {
            var data = new byte[256];
            RandomNumberGenerator.Fill(data);
            var key = new RsaJwk
            {
                N = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
                E = "AQAB",
                D = "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
                P = "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
                Q = "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
                DP = "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
                DQ = "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
                QI = "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
                Alg = KeyManagementAlgorithm.RsaPkcs1
            };

            var descriptor = new BinaryJweDescriptor(data);
            descriptor.Key = key;
            descriptor.EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256;

            JwtWriter writer = new JwtWriter();
            var value = writer.WriteToken(descriptor);
            Assert.NotNull(value);

            var reader = new JwtReader(key);
            var result = reader.TryReadToken(value, TokenValidationPolicy.NoValidation);
            Assert.Equal(TokenValidationStatus.Success, result.Status);

            var jwt = result.Token;
            Assert.Equal(data, jwt.Binary);
        }

        [Fact]
        public void Write_Compressed()
        {
            var plaintext = "Live long and prosper.".PadRight(992 * 100, 'X');

            var descriptor = new PlaintextJweDescriptor(plaintext);
            descriptor.Key = RsaKey;
            descriptor.EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256;
            descriptor.CompressionAlgorithm = CompressionAlgorithm.Deflate;

            JwtWriter writer = new JwtWriter();
            var value = writer.WriteToken(descriptor);

            var reader = new JwtReader(RsaKey);
            var result = reader.TryReadToken(value, TokenValidationPolicy.NoValidation);
            Assert.Equal(TokenValidationStatus.Success, result.Status);

            var jwt = result.Token;

            Assert.Equal(plaintext, jwt.Plaintext);
        }

        public static IEnumerable<object[]> GetDescriptors()
        {
            foreach (var item in Tokens.Descriptors)
            {
                yield return new object[] { item.Key };
            }
        }
    }
}
