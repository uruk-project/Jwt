using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class JwtWriter_BasicTokenEncrypted
    {
        private static readonly string SharedKey = "{" +
"\"kty\": \"oct\"," +
"\"use\": \"sig\"," +
"\"kid\": \"kid-hs256\"," +
"\"k\": \"HWF8LuG4F9TNWNsTKNvAlxpcj_e4Cp2BFmEMCAoWEOQ\"," +
"\"alg\": \"HS256\"" +
"}";

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SharedKey);
        private static readonly SymmetricJwk CustomSharedKey = JsonWebKey.FromJson<SymmetricJwk>(SharedKey);

        private static readonly SecurityTokenDescriptor WilsonDirectDescriptor = CreateWilsonSmallDescriptor(SecurityAlgorithms.Direct);
        private static readonly SecurityTokenDescriptor WilsonKWDescriptor = CreateWilsonSmallDescriptor(SecurityAlgorithms.Aes256KW);

        private static readonly JsonWebTokenDescriptor CustomDirectDescriptor = CreateCustomSmallDescriptor(SecurityAlgorithms.Direct);
        private static readonly JsonWebTokenDescriptor CustomKWDescriptor = CreateCustomSmallDescriptor(SecurityAlgorithms.Aes256KW);

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

        private static JsonWebTokenDescriptor CreateCustomSmallDescriptor(string cekAlgorithm)
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
                SigningKey = CustomSharedKey,
                EncryptingKey = CustomSharedKey,
                EncryptionAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256,
                ContentEncryptionAlgorithm = cekAlgorithm
            };
            return descriptor;
        }

        private static SecurityTokenDescriptor CreateWilsonSmallDescriptor(string cekAlgorithm)
        {
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            //var jti = "756E69717565206964656E746966696572";
            var descriptor = new SecurityTokenDescriptor()
            {
                IssuedAt = issuedAt,
                Expires = expires,
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = new SigningCredentials(WilsonSharedKey, CustomSharedKey.Alg),
                EncryptingCredentials = new EncryptingCredentials(WilsonSharedKey, cekAlgorithm, SecurityAlgorithms.Aes128CbcHmacSha256)
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
