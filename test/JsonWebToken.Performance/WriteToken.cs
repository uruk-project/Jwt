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

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class WriteToken
    {
        private static readonly SymmetricJwk SymmetricKey = new SymmetricJwk
        {
            Use = "sig",
            Kid = "kid-hs256",
            K = "GdaXeVyiJwKmz5LFhcbcng",
            Alg = "HS256"
        };

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SymmetricKey.ToString());

        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();

        public static readonly JsonWebTokenWriter Writer = new JsonWebTokenWriter();

        private static readonly Dictionary<string, JwsDescriptor> JwtPayloads = CreateJwtDescriptors();
        private static readonly Dictionary<string, Dictionary<string, object>> DictionaryPayloads = CreateDictionaryDescriptors();
        private static readonly Dictionary<string, SecurityTokenDescriptor> WilsonPayloads = CreateWilsonDescriptors();

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetPayloads))]
        public void Jwt(string payload)
        {
            var value = Writer.WriteToken(JwtPayloads[payload]);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetPayloads))]
        public void Wilson(string payload)
        {
            var token = Handler.CreateEncodedJwt(WilsonPayloads[payload]);
        }

        //[Benchmark]
        [ArgumentsSource(nameof(GetPayloads))]
        public void JoseDotNet(string payload)
        {
            var value = Jose.JWT.Encode(DictionaryPayloads[payload], SymmetricKey.RawK, JwsAlgorithm.HS256);
        }

        //[Benchmark]
        [ArgumentsSource(nameof(GetPayloads))]
        public void JwtDotNet(string payload)
        {
            var value = JwtDotNetEncoder.Encode(DictionaryPayloads[payload], SymmetricKey.RawK);
        }

        public IEnumerable<object[]> GetPayloads()
        {
            //yield return new[] { "empty" };
            yield return new[] { "small" };
            //yield return new[] { "medium" };
            yield return new[] { "big" };
        }

        private static Dictionary<string, JwsDescriptor> CreateJwtDescriptors()
        {
            var descriptors = new Dictionary<string, JwsDescriptor>();
            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    Key = SymmetricKey
                };

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "exp":
                            descriptor.AddClaim(property.Name, EpochTime.ToDateTime((long)property.Value));
                            break;
                        default:
                            descriptor.AddClaim(property.Name, (string)property.Value);
                            break;
                    }
                }

                descriptors.Add(payload.Key, descriptor);
            }

            return descriptors;
        }

        private static Dictionary<string, SecurityTokenDescriptor> CreateWilsonDescriptors()
        {
            var descriptors = new Dictionary<string, SecurityTokenDescriptor>();
            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new SecurityTokenDescriptor()
                {
                    SigningCredentials = new SigningCredentials(WilsonSharedKey, SymmetricKey.Alg),
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.ContainsKey("exp") ? EpochTime.ToDateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.ContainsKey("iat") ? EpochTime.ToDateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
                };

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "exp":
                          //  descriptor.Subject.AddClaim(new Claim(property.Name, (string)property.Value));
                            break;
                        default:
                            descriptor.Subject.AddClaim(new Claim(property.Name, (string)property.Value));
                            break;
                    }
                }

                descriptors.Add(payload.Key, descriptor);
            }

            return descriptors;
        }

        private static Dictionary<string, Dictionary<string, object>> CreateDictionaryDescriptors()
        {
            var descriptors = new Dictionary<string, Dictionary<string, object>>();
            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new Dictionary<string, object>();

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "exp":
                            descriptor.Add(property.Name, (long)property.Value);
                            break;
                        default:
                            descriptor.Add(property.Name, (string)property.Value);
                            break;
                    }
                }

                descriptors.Add(payload.Key, descriptor);
            }

            return descriptors;
        }
    }
}