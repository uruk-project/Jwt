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
    [Config(typeof(DefaultCoreConfig))]
    public class JwtWriter_BasicTokenEncrypted
    {
        private static readonly SymmetricJwk SigningKey = new SymmetricJwk
        {
            Use = "sig",
            Kid = "signing-key",
            K = "HWF8LuG4F9TNWNsTKNvAlxpcj_e4Cp2BFmEMCAoWEOQ",
            Alg = SecurityAlgorithms.HmacSha256
        };
        private static readonly SymmetricJwk DirectEncryptionKey = new SymmetricJwk
        {
            Use = "enc",
            Kid = "encryption-key",
            K = "HWF8LuG4F9TNWNsTKNvAlxpcj_e4Cp2BFmEMCAoWEOQ",
            Alg = SecurityAlgorithms.Direct
        };
        private static readonly SymmetricJwk KeyWrapEncryptionKey = new SymmetricJwk
        {
            Use = "enc",
            Kid = "encryption-key",
            K = "HWF8LuG4F9TNWNsTKNvAlxpcj_e4Cp2BFmEMCAoWEOQ",
            Alg = SecurityAlgorithms.Aes256KW
        };

        private static readonly SecurityTokenDescriptor WilsonDirectDescriptor = CreateWilsonDescriptor(DirectEncryptionKey.ToString());
        private static readonly SecurityTokenDescriptor WilsonKWDescriptor = CreateWilsonDescriptor(KeyWrapEncryptionKey.ToString());

        private static readonly JweDescriptor CustomDirectDescriptor = CreateCustomDescriptor(DirectEncryptionKey);
        private static readonly JweDescriptor CustomKWDescriptor = CreateCustomDescriptor(KeyWrapEncryptionKey);

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

        private static JweDescriptor CreateCustomDescriptor(JsonWebKey encryptionKey)
        {
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            //var jti = "756E69717565206964656E746966696572";
            var jws = new JwsDescriptor
            {
                IssuedAt = issuedAt,
                ExpirationTime = expires,
                Issuer = issuer,
                Audience = audience,
                Key = SigningKey
            };
            var descriptor = new JweDescriptor(jws)               
                {
                    Key = encryptionKey,
                    EncryptionAlgorithm = SecurityAlgorithms.Aes128CbcHmacSha256
                };
            return descriptor;
        }

        private static SecurityTokenDescriptor CreateWilsonDescriptor(string encryptionKeyJson)
        {
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            //var jti = "756E69717565206964656E746966696572";
            var encryptionKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(encryptionKeyJson);
            var signingKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SigningKey.ToString());
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
