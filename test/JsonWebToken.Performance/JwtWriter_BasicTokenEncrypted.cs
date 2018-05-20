using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class JwtWriter_BasicTokenEncrypted
    {
        private static readonly string SigningKey = "{" +
"\"kty\": \"oct\"," +
"\"use\": \"sig\"," +
"\"kid\": \"signing-key\"," +
"\"k\": \"HWF8LuG4F9TNWNsTKNvAlxpcj_e4Cp2BFmEMCAoWEOQ\"," +
"\"alg\": \"" + SecurityAlgorithms.HmacSha256 + "\"" +
"}";
        private static readonly string DirectEncryptionKey = "{" +
"\"kty\": \"oct\"," +
"\"use\": \"enc\"," +
"\"kid\": \"encryption-key\"," +
"\"k\": \"HWF8LuG4F9TNWNsTKNvAlxpcj_e4Cp2BFmEMCAoWEOQ\"," +
"\"alg\": \"" + SecurityAlgorithms.Direct + "\"" +
"}";
        private static readonly string KeyWrapEncryptionKey = "{" +
"\"kty\": \"oct\"," +
"\"use\": \"enc\"," +
"\"kid\": \"encryption-key\"," +
"\"k\": \"HWF8LuG4F9TNWNsTKNvAlxpcj_e4Cp2BFmEMCAoWEOQ\"," +
"\"alg\": \"" + SecurityAlgorithms.Aes256KW + "\"" +
"}";
        private static readonly SymmetricJwk CustomSigningKeyKey = JsonWebKey.FromJson<SymmetricJwk>(SigningKey);

        private static readonly SecurityTokenDescriptor WilsonDirectDescriptor = CreateWilsonSmallDescriptor(DirectEncryptionKey);
        private static readonly SecurityTokenDescriptor WilsonKWDescriptor = CreateWilsonSmallDescriptor(KeyWrapEncryptionKey);

        private static readonly JsonWebTokenDescriptor CustomDirectDescriptor = CreateCustomSmallDescriptor(DirectEncryptionKey);
        private static readonly JsonWebTokenDescriptor CustomKWDescriptor = CreateCustomSmallDescriptor(KeyWrapEncryptionKey);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

        public static readonly JsonWebTokenWriter Writer = new JsonWebTokenWriter();


        [Benchmark(Baseline = true)]
        public void Wilson_Direct()
        {
            var token = Handler.CreateEncodedJwt(WilsonDirectDescriptor);
        }

        [Benchmark]
        public void Wilson_KeyWrap()
        {
            var token = Handler.CreateEncodedJwt(WilsonKWDescriptor);
        }

        [Benchmark]
        public void Jwt_Direct()
        {
            var value = Writer.WriteToken(CustomDirectDescriptor);
        }

        [Benchmark]
        public void Jwt_KeyWrap()
        {
            var value = Writer.WriteToken(CustomKWDescriptor);
        }

        private static JsonWebTokenDescriptor CreateCustomSmallDescriptor(string encryptionKey)
        {
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            //var jti = "756E69717565206964656E746966696572";
            var descriptor = new JsonWebTokenDescriptor()
            {
                IssuedAt = issuedAt,
                Expires = expires,
                Issuer = issuer,
                Audience = audience,
                SigningKey = CustomSigningKeyKey,
                EncryptingKey = JsonWebKey.FromJson(encryptionKey),
                EncryptionAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256
            };
            return descriptor;
        }

        private static SecurityTokenDescriptor CreateWilsonSmallDescriptor(string encryptionKeyJson)
        {
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            //var jti = "756E69717565206964656E746966696572";
            var encryptionKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(encryptionKeyJson);
            var signingKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SigningKey);
            var descriptor = new SecurityTokenDescriptor()
            {
                IssuedAt = issuedAt,
                Expires = expires,
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = new SigningCredentials(signingKey, signingKey.Alg),
                EncryptingCredentials = new EncryptingCredentials(encryptionKey, encryptionKey.Alg, SecurityAlgorithms.Aes128CbcHmacSha256)
            };
            return descriptor;
        }

        private static Dictionary<string, object> CreateJoseDotNetSmallPayload()
        {
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            //var jti = "756E69717565206964656E746966696572";
            var payload = new Dictionary<string, object>()
            {
              { "iat", issuedAt },
              { "exp", expires },
              { "iss", issuer },
              { "aud", audience }
            };
            return payload;
        }
    }
}
