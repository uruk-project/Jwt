using BenchmarkDotNet.Attributes;
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
using Microsoft.IdentityModel.JsonWebTokens;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class WriteToken
    {
        private static readonly SymmetricJwk SigningKey = Tokens.SigningKey;

        private static readonly SymmetricJwk EncryptionKey = Tokens.EncryptionKey;

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SigningKey.ToString());

        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();
        public static readonly JsonWebTokenHandler Handler2 = new JsonWebTokenHandler();

        public static readonly SigningCredentials signingCredentials = new SigningCredentials(WilsonSharedKey, SigningKey.Alg);

        public static readonly JsonWebTokenWriter Writer = new JsonWebTokenWriter();

        private static readonly Dictionary<string, JwtDescriptor> JwtPayloads = CreateJwtDescriptors();
        private static readonly Dictionary<string, Dictionary<string, object>> DictionaryPayloads = CreateDictionaryDescriptors();
        private static readonly Dictionary<string, SecurityTokenDescriptor> WilsonPayloads = CreateWilsonDescriptors();

        static WriteToken()
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }

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

        [Benchmark]
        [ArgumentsSource(nameof(GetNotEncryptedPayloads))]
        public void Wilson2(string payload)
        {
            var token = Handler2.CreateToken(Tokens.Payloads[payload.Substring(4)], signingCredentials);
        }

        //[Benchmark]
        [ArgumentsSource(nameof(GetPayloads))]
        public void JoseDotNet(string payload)
        {
            if (payload.StartsWith("JWE-"))
            {
                payload = payload.Substring(4, payload.Length - 4);
                var value = Jose.JWT.Encode(DictionaryPayloads[payload], SigningKey.RawK, JwsAlgorithm.HS256);
                value = Jose.JWT.Encode(value, EncryptionKey.RawK, JweAlgorithm.A128KW, JweEncryption.A128CBC_HS256);
            }
            else
            {
                var value = Jose.JWT.Encode(DictionaryPayloads[payload], SigningKey.RawK, JwsAlgorithm.HS256);
            }
        }

        //[Benchmark]
        [ArgumentsSource(nameof(GetNotEncryptedPayloads))]
        public void JwtDotNet(string payload)
        {
            var value = JwtDotNetEncoder.Encode(DictionaryPayloads[payload], SigningKey.RawK);
        }

        public IEnumerable<object[]> GetPayloads()
        {
            yield return new[] { "JWS-empty" };
            yield return new[] { "JWS-small" };
            yield return new[] { "JWS-medium" };
            yield return new[] { "JWS-big" };
            yield return new[] { "JWE-empty" };
            yield return new[] { "JWE-small" };
            yield return new[] { "JWE-medium" };
            yield return new[] { "JWE-big" };
        }

        public IEnumerable<object[]> GetNotEncryptedPayloads()
        {
            yield return new[] { "JWS-empty" };
            yield return new[] { "JWS-small" };
            yield return new[] { "JWS-medium" };
            yield return new[] { "JWS-big" };
        }

        //public IEnumerable<object[]> GetJsonPayloads()
        //{
        //    yield return new[] { "empty" };
        //    yield return new[] { "small" };
        //    yield return new[] { "medium" };
        //    yield return new[] { "big" };
        //}
        private static Dictionary<string, JwtDescriptor> CreateJwtDescriptors()
        {
            var descriptors = new Dictionary<string, JwtDescriptor>();
            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    Key = SigningKey
                };

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            descriptor.AddClaim(property.Name, EpochTime.ToDateTime((long)property.Value));
                            break;
                        default:
                            descriptor.AddClaim(property.Name, (string)property.Value);
                            break;
                    }
                }

                descriptors.Add("JWS-" + payload.Key, descriptor);
            }

            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    Key = SigningKey
                };

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            descriptor.AddClaim(property.Name, EpochTime.ToDateTime((long)property.Value));
                            break;
                        default:
                            descriptor.AddClaim(property.Name, (string)property.Value);
                            break;
                    }
                }

                var jwe = new JweDescriptor
                {
                    Payload = descriptor,
                    Key = EncryptionKey,
                    EncryptionAlgorithm = ContentEncryptionAlgorithms.Aes128CbcHmacSha256
                };

                descriptors.Add("JWE-" + payload.Key, jwe);
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
                    SigningCredentials = new SigningCredentials(WilsonSharedKey, SigningKey.Alg),
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.ContainsKey("exp") ? EpochTime.ToDateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.ContainsKey("iat") ? EpochTime.ToDateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
                };

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            break;
                        default:
                            descriptor.Subject.AddClaim(new Claim(property.Name, (string)property.Value));
                            break;
                    }
                }

                descriptors.Add("JWS-" + payload.Key, descriptor);
            }

            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new SecurityTokenDescriptor()
                {
                    SigningCredentials = new SigningCredentials(WilsonSharedKey, SigningKey.Alg),
                    EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(EncryptionKey.RawK), KeyManagementAlgorithms.Aes128KW, ContentEncryptionAlgorithms.Aes128CbcHmacSha256),
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.ContainsKey("exp") ? EpochTime.ToDateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.ContainsKey("iat") ? EpochTime.ToDateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
                };

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            break;
                        default:
                            descriptor.Subject.AddClaim(new Claim(property.Name, (string)property.Value));
                            break;
                    }
                }

                descriptors.Add("JWE-" + payload.Key, descriptor);
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
                        case "nbf":
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