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
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    [Config(typeof(DefaultCoreConfig))]
    public class JwtWriter_BigToken
    {
        private static readonly SymmetricJwk SymmetricKey = new SymmetricJwk
        {
            Use = "sig",
            Kid = "kid-hs256",
            K = "GdaXeVyiJwKmz5LFhcbcng",
            Alg = "HS256"
        };

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SymmetricKey.ToString());
        
        private static readonly string BigClaim = CreateClaim();
      
        private static readonly SecurityTokenDescriptor WilsonDescriptor = CreateWilsonDescriptor();
        private static readonly JwsDescriptor JwtDescriptor = CreateJwtDescriptor();

        private static readonly Dictionary<string, object> JoseDotNetDescriptor = CreateJoseDotNetPayload();
        private static readonly byte[] JoseDotNetSharedKey = SymmetricKey.RawK;

        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

        public static readonly JsonWebTokenWriter Writer = new JsonWebTokenWriter();

        private static string CreateClaim()
        {
            var data = new byte[1024 * 1024];
            using (var rnd = RandomNumberGenerator.Create())
            {
                rnd.GetBytes(data);
            }

            return Base64Url.Base64UrlEncode(data);
        }

        [Benchmark(Baseline = true)]
        public void Wilson()
        {
            var token = Handler.CreateEncodedJwt(WilsonDescriptor);
        }

        [Benchmark]
        public void Jwt()
        {
            var value = Writer.WriteToken(JwtDescriptor);
        }

        [Benchmark]
        public void JoseDotNet()
        {
            var value = Jose.JWT.Encode(JoseDotNetDescriptor, JoseDotNetSharedKey, JwsAlgorithm.HS256);
        }

        [Benchmark]
        public void JwtDotNet()
        {
            var value = JwtDotNetEncoder.Encode(JoseDotNetDescriptor, SymmetricKey.RawK);
        }

        private static JwsDescriptor CreateJwtDescriptor()
        {
            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            //var jti = "756E69717565206964656E746966696572";
            var descriptor = new JwsDescriptor()
            {
                IssuedAt = issuedAt,
                ExpirationTime = expires,
                Issuer = issuer,
                Audience = audience,
                Key = SymmetricKey
            };
            descriptor.Payload["big_claim"] = BigClaim;
            return descriptor;
        }

        private static SecurityTokenDescriptor CreateWilsonDescriptor()
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
                SigningCredentials = new SigningCredentials(WilsonSharedKey, SymmetricKey.Alg),
                Subject = new ClaimsIdentity(new List<Claim> { new Claim("big_claim", BigClaim) })
            };
            return descriptor;
        }

        private static Dictionary<string, object> CreateJoseDotNetPayload()
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
              { "aud", audience },
              { "big_claim", BigClaim }
            };
            return payload;
        }
    }
}
