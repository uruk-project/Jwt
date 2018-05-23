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
    public class JwtWriter_BigToken
    {
        private static readonly string SharedKey = "{" +
"\"kty\": \"oct\"," +
"\"use\": \"sig\"," +
"\"kid\": \"kid-hs256\"," +
"\"k\": \"GdaXeVyiJwKmz5LFhcbcng\"," +
"\"alg\": \"HS256\"" +
"}";

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SharedKey);
        private static readonly SymmetricJwk CustomSharedKey = JsonWebKey.FromJson<SymmetricJwk>(SharedKey);

        private static readonly string BigClaim = CreateBigClaim();
      
        //private static readonly SecurityTokenDescriptor WilsonEmptyDescriptor;
        private static readonly SecurityTokenDescriptor WilsonBigDescriptor = CreateWilsonBigDescriptor();
        //private static readonly SecurityTokenDescriptor WilsonMediumDescriptor;
        //private static readonly SecurityTokenDescriptor WilsonBigDescriptor;

        //private static readonly JsonWebTokenDescriptor CustomEmptyDescriptor;
        private static readonly JwsDescriptor JwtBigDescriptor = CreateCustomBigDescriptor();
        //private static readonly JsonWebTokenDescriptor CustomMediumDescriptor;
        //private static readonly JsonWebTokenDescriptor CustomBigDescriptor;

        private static readonly Dictionary<string, object> JoseDotNetBigDescriptor = CreateJoseDotNetBigPayload();
        private static readonly byte[] JoseDotNetSharedKey = CustomSharedKey.RawK;

        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

        public static readonly JsonWebTokenWriter Writer = new JsonWebTokenWriter();



        private static string CreateBigClaim()
        {
            var data = new byte[1024 * 1024];
            RandomNumberGenerator.Fill(data);
            return Encoding.UTF8.GetString(data);
        }

        //[Benchmark(Baseline = true)]
        public void Wilson()
        {
            var token = Handler.CreateEncodedJwt(WilsonBigDescriptor);
        }

        [Benchmark]
        public void jwt()
        {
            var value = Writer.WriteToken(JwtBigDescriptor);
        }

        //[Benchmark]
        public void JoseDotNet()
        {
            var value = Jose.JWT.Encode(JoseDotNetBigDescriptor, JoseDotNetSharedKey, JwsAlgorithm.HS256);
        }

        //[Benchmark]
        public void JwtDotNet()
        {
            var value = JwtDotNetEncoder.Encode(JoseDotNetBigDescriptor, CustomSharedKey.RawK);
        }

        private static JwsDescriptor CreateCustomBigDescriptor()
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
                Key = CustomSharedKey
            };
            descriptor.Payload["big_claim"] = BigClaim;
            return descriptor;
        }

        private static SecurityTokenDescriptor CreateWilsonBigDescriptor()
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
                Subject = new ClaimsIdentity(new List<Claim> { new Claim("big_claim", BigClaim) })
            };
            return descriptor;
        }

        private static Dictionary<string, object> CreateJoseDotNetBigPayload()
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
