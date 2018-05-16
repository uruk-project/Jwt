using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Loggers;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Toolchains.CsProj;
using BenchmarkDotNet.Toolchains.DotNetCli;
using BenchmarkDotNet.Validators;
using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;
using Jwt = JsonWebToken;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text.RegularExpressions;

namespace JsonWebToken.Performance
{

    [MemoryDiagnoser]
    //[Config(typeof(DefaultCoreConfig))]
    public class JwtWriter_EmptyToken
    {
        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

        public static readonly JsonWebTokenWriter Writer = new JsonWebTokenWriter();

        [Benchmark(Baseline = true)]
        public void Wilson()
        {
            var descriptor = new SecurityTokenDescriptor();
            var value = Handler.CreateEncodedJwt(descriptor);
        }


        [Benchmark]
        public void JoseDotNet()
        {
            var payload = new Dictionary<string, object>();
            var value = Jose.JWT.Encode(payload, string.Empty, JwsAlgorithm.none);
        }

        [Benchmark]
        public void JwtDotNet()
        {
            var payload = new Dictionary<string, object>();
            var value = JwtDotNetEncoder.Encode(payload, string.Empty);
        }

        [Benchmark]
        public void Custom()
        {
            var descriptor = new JsonWebTokenDescriptor();
            var value = Writer.WriteToken(descriptor);
        }
    }

    [MemoryDiagnoser]
    //[Config(typeof(DefaultCoreConfig))]
    public class JwtWriter_BasicToken
    {
        private static readonly string SharedKey = "{" +
"\"kty\": \"oct\"," +
"\"use\": \"sig\"," +
"\"kid\": \"kid-hs256\"," +
"\"k\": \"GdaXeVyiJwKmz5LFhcbcng\"," +
"\"alg\": \"HS256\"" +
"}";

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SharedKey);
        private static readonly SymmetricJwk CustomSharedKey = JsonWebKey.FromJson(SharedKey) as SymmetricJwk;

        //private static readonly SecurityTokenDescriptor WilsonEmptyDescriptor;
        private static readonly SecurityTokenDescriptor WilsonSmallDescriptor = CreateWilsonSmallDescriptor();
        //private static readonly SecurityTokenDescriptor WilsonMediumDescriptor;
        //private static readonly SecurityTokenDescriptor WilsonBigDescriptor;

        //private static readonly JsonWebTokenDescriptor CustomEmptyDescriptor;
        private static readonly JsonWebTokenDescriptor CustomSmallDescriptor = CreateCustomSmallDescriptor();
        //private static readonly JsonWebTokenDescriptor CustomMediumDescriptor;
        //private static readonly JsonWebTokenDescriptor CustomBigDescriptor;

        private static readonly Dictionary<string, object> JoseDotNetSmallDescriptor = CreateJoseDotNetSmallPayload();
        private static readonly byte[] JoseDotNetSharedKey = CustomSharedKey.RawK;

        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

        public static readonly JsonWebTokenWriter Writer = new JsonWebTokenWriter();
        

        [Benchmark(Baseline = true)]
        public void Wilson()
        {
            var token = Handler.CreateEncodedJwt(WilsonSmallDescriptor);
        }

        [Benchmark]
        public void Custom()
        {
            var value = Writer.WriteToken(CustomSmallDescriptor);
        }

        [Benchmark]
        public void JoseDotNet()
        {
            var value = Jose.JWT.Encode(JoseDotNetSmallDescriptor, JoseDotNetSharedKey, JwsAlgorithm.HS256);
        }

        [Benchmark]
        public void JwtDotNet()
        {
            var value = JwtDotNetEncoder.Encode(JoseDotNetSmallDescriptor, CustomSharedKey.RawK);
        }

        private static JsonWebTokenDescriptor CreateCustomSmallDescriptor()
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
                SigningKey = CustomSharedKey
            };
            return descriptor;
        }

        private static SecurityTokenDescriptor CreateWilsonSmallDescriptor()
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
                SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(WilsonSharedKey, CustomSharedKey.Alg)
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

    [MemoryDiagnoser]
    public class JwtReader_Valid
    {
        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();
        

        private const string Token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.i2JGGP64mggd3WqUj7oX8_FyYh9e_m1MNWI9Q-f-W3g";
        
        private static readonly SymmetricJwk CustomSharedKey = JsonWebKey.FromJson(SharedKey) as SymmetricJwk;
        private static readonly string SharedKey = "{" +
                                                   "\"kty\": \"oct\"," +
                                                   "\"use\": \"sig\"," +
                                                   "\"kid\": \"kid-hs256\"," +
                                                   "\"k\": \"GdaXeVyiJwKmz5LFhcbcng\"," +
                                                   "\"alg\": \"HS256\"" +
                                                   "}";
        public static readonly JsonWebTokenReader Reader = new JsonWebTokenReader(CustomSharedKey);

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SharedKey);

        [Benchmark(Baseline = true)]
        public void Wilson()
        {
            var result = Handler.ReadJwtToken(Token);
        }

        [Benchmark]
        public void Custom()
        {
            var result = Reader.TryReadToken(Token, new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                RequireSignedTokens = false, 
                ValidateLifetime = false, 
            });
        }

        [Benchmark]
        public void JoseDotNet()
        {
            var value = Jose.JWT.Decode(Token, CustomSharedKey.RawK, JwsAlgorithm.HS256);
        }

        [Benchmark]
        public void JwtDotNet()
        {
            var value = JwtDotNetDecoder.Decode(Token, CustomSharedKey.RawK, false);
        }
    }



    [MemoryDiagnoser]
    public class JwtReaderValidation_SmallValid
    {
        private const string Token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.i2JGGP64mggd3WqUj7oX8_FyYh9e_m1MNWI9Q-f-W3g";

        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

        private static readonly string SharedKey = "{" +
                                                   "\"kty\": \"oct\"," +
                                                   "\"use\": \"sig\"," +
                                                   "\"kid\": \"kid-hs256\"," +
                                                   "\"k\": \"GdaXeVyiJwKmz5LFhcbcng\"," +
                                                   "\"alg\": \"HS256\"" +
                                                   "}";

        private static readonly SymmetricJwk CustomSharedKey = JsonWebKey.FromJson(SharedKey) as SymmetricJwk;
        public static readonly JsonWebTokenReader Reader = new JsonWebTokenReader(CustomSharedKey);

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SharedKey);

        [Benchmark(Baseline = true)]
        public void Wilson()
        {
            var result = Handler.ValidateToken(Token, new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                IssuerSigningKey = WilsonSharedKey
            }, out var securityToken);
        }

        [Benchmark]
        public void Custom()
        {
            var result = Reader.TryReadToken(Token, new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false
            });
        }

        [Benchmark]
        public void JoseDotNet()
        {
            var value = Jose.JWT.Decode(Token, CustomSharedKey.RawK, JwsAlgorithm.HS256);
        }

        [Benchmark]
        public void JwtDotNet()
        {
            var value = JwtDotNetDecoder.Decode(Token, CustomSharedKey.RawK, true);
        }
    }

    [MemoryDiagnoser]
    public class JwtReaderValidation_SmallExpired
    {
        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();
        
        private const string Token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNDA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.eQCYbBSuHsDLzuYep9-PkFgCi-HhaX9LyZAh1r3xSQY";

        private static readonly string SharedKey = "{" +
                                                   "\"kty\": \"oct\"," +
                                                   "\"use\": \"sig\"," +
                                                   "\"kid\": \"kid-hs256\"," +
                                                   "\"k\": \"GdaXeVyiJwKmz5LFhcbcng\"," +
                                                   "\"alg\": \"HS256\"" +
                                                   "}";
        private static readonly SymmetricJwk CustomSharedKey = JsonWebKey.FromJson(SharedKey) as SymmetricJwk;
        public static readonly JsonWebTokenReader Reader = new JsonWebTokenReader(CustomSharedKey);

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SharedKey);

        [Benchmark(Baseline = true)]
        public void Wilson()
        {
            try
            {
                var result = Handler.ValidateToken(Token, new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    IssuerSigningKey = WilsonSharedKey
                }, out var securityToken);
            }
            catch (SecurityTokenExpiredException)
            {
            }
        }

        [Benchmark]
        public void Custom()
        {
            var result = Reader.TryReadToken(Token, new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false
            });
        }

        [Benchmark]
        public void JoseDotNet()
        {

            try
            {
                var value = Jose.JWT.Decode(Token, CustomSharedKey.RawK, JwsAlgorithm.HS256);
            }
            catch 
            {
            }
        }

        [Benchmark]
        public void JwtDotNet()
        {
            try
            {
                var value = JwtDotNetDecoder.Decode(Token, CustomSharedKey.RawK, true);
            }
            catch { }
        }
    }



    internal class DefaultCoreConfig : ManualConfig
    {
        public DefaultCoreConfig()
        {
            Add(ConsoleLogger.Default);
            Add(MarkdownExporter.GitHub);

            Add(MemoryDiagnoser.Default);
            Add(StatisticColumn.OperationsPerSecond);
            Add(DefaultColumnProviders.Instance);

            Add(JitOptimizationsValidator.FailOnError);

            Add(Job.Core
                .With(CsProjCoreToolchain.From(NetCoreAppSettings.NetCoreApp21))
                .With(new GcMode { Server = true })
                .With(RunStrategy.Throughput));
        }
    }
}
