using System;
using System.Buffers;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JsonWebToken.Performance
{
    public abstract class WriteToken
    {
        private static readonly byte[] SigningKeyArray = Tokens.SigningKey.ToArray();
        private static readonly byte[] EncryptionKeyArray = Tokens.EncryptionKey.ToArray();

        private static readonly IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
        private static readonly IJsonSerializer serializer = new JsonNetSerializer();
        private static readonly IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        private static readonly IDateTimeProvider dateTimeProvider = new UtcDateTimeProvider();
        public static readonly IJwtEncoder JwtDotNetEncoder = new JwtEncoder(algorithm, serializer, urlEncoder);
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();
        public static readonly JsonWebTokenHandler Handler2 = new JsonWebTokenHandler();

        public static readonly SigningCredentials signingCredentials = new SigningCredentials(JsonWebKey.Create(Tokens.SigningKey.ToString()), ((SignatureAlgorithm)Tokens.SigningKey.Alg!).Name);

        public static readonly JwtWriter Writer = new JwtWriter() { EnableHeaderCaching = true };


        private static readonly FixedSizedBufferWriter _output = new FixedSizedBufferWriter(8192);

        static WriteToken()
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }

        public abstract byte[] Jwt(BenchmarkPayload payload);

        protected byte[] JwtCore(JwtDescriptor payload)
        {
            Writer.WriteToken(payload, _output);
            _output.Clear();
            return _output.Buffer;
        }

        public abstract string Wilson(BenchmarkPayload payload);

        protected string WilsonCore(SecurityTokenDescriptor payload)
        {
            return Handler.CreateEncodedJwt(payload);
        }

        public abstract string WilsonJwt(BenchmarkPayload payload);

        protected string WilsonJwtCore(string payload)
        {
            return Handler2.CreateToken(payload, signingCredentials);
        }

        public abstract string JoseDotNet(BenchmarkPayload payload);

        protected string JoseDotNetJwsCore(Dictionary<string, object> payload)
        {
            return Jose.JWT.Encode(payload, SigningKeyArray, JwsAlgorithm.HS256);
        }

        protected string JoseDotNetJweCore(Dictionary<string, object> payload)
        {
            var value = Jose.JWT.Encode(payload, SigningKeyArray, JwsAlgorithm.HS256);
            return Jose.JWT.Encode(value, EncryptionKeyArray, JweAlgorithm.A128KW, JweEncryption.A128CBC_HS256);
        }

        public abstract string JwtDotNet(BenchmarkPayload payload);

        protected string JwtDotNetJwsCore(Dictionary<string, object> payload)
        {
            return JwtDotNetEncoder.Encode(payload, SigningKeyArray);
        }
        protected string JwtDotNetJwtCore(Dictionary<string, object> payload)
        {
            return JwtDotNetEncoder.Encode(payload, (byte[])null!);
        }


        public abstract IEnumerable<string> GetPayloads();

        public IEnumerable<BenchmarkPayload> GetPayloadValues()
        {
            foreach (var item in GetPayloads())
            {
                yield return new BenchmarkPayload(item);
            }
        }
    }

    internal class FixedSizedBufferWriter : IBufferWriter<byte>
    {
        private readonly byte[] _buffer;
        private int _count;

        public FixedSizedBufferWriter(int capacity)
        {
            _buffer = new byte[capacity];
        }

        public void Clear()
        {
            _count = 0;
        }

        public byte[] Buffer => _buffer;

        public Memory<byte> GetMemory(int minimumLength = 0) => _buffer.AsMemory(_count);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Span<byte> GetSpan(int minimumLength = 0) => _buffer.AsSpan(_count);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Advance(int bytes)
        {
            _count += bytes;
        }
    }


    public class BenchmarkPayload
    {
        private static readonly SymmetricJwk SigningKey = Tokens.SigningKey;
        private static readonly SymmetricJwk EncryptionKey = Tokens.EncryptionKey;

        private static readonly JsonWebKey WilsonSharedKey = JsonWebKey.Create(SigningKey.ToString());

        private static readonly Dictionary<string, JwtDescriptor> JwtPayloads = CreateJwtDescriptors();
        private static readonly Dictionary<string, Dictionary<string, object>> DictionaryPayloads = CreateDictionaryDescriptors();
        private static readonly Dictionary<string, SecurityTokenDescriptor> WilsonPayloads = CreateWilsonDescriptors();

        public BenchmarkPayload(string name)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            JwtDescriptor = JwtPayloads[name];
            JoseDescriptor = DictionaryPayloads[name];
            WilsonDescriptor = WilsonPayloads[name];
            WilsonJwtDescriptor = Tokens.Payloads[name.Substring(4)].ToString();
        }

        public string Name { get; }

        public JwtDescriptor JwtDescriptor { get; }

        public Dictionary<string, object> JoseDescriptor { get; }

        public SecurityTokenDescriptor WilsonDescriptor { get; }

        public string WilsonJwtDescriptor { get; }

        public override string ToString()
        {
            return Name;
        }

        private static Dictionary<string, JwtDescriptor> CreateJwtDescriptors()
        {
            var descriptors = new Dictionary<string, JwtDescriptor>();
            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    Algorithm = SignatureAlgorithm.None
                };

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            descriptor.AddClaim(property.Name, Microsoft.IdentityModel.Tokens.EpochTime.DateTime((long)property.Value));
                            break;
                        default:
                            descriptor.AddClaim(property.Name, (string)property.Value);
                            break;
                    }
                }

                descriptors.Add("JWT-" + payload.Key, descriptor);
            }

            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    SigningKey = SigningKey
                };

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            descriptor.AddClaim(property.Name, Microsoft.IdentityModel.Tokens.EpochTime.DateTime((long)property.Value));
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
                    SigningKey = SigningKey
                };

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            descriptor.AddClaim(property.Name, Microsoft.IdentityModel.Tokens.EpochTime.DateTime((long)property.Value));
                            break;
                        default:
                            descriptor.AddClaim(property.Name, (string)property.Value);
                            break;
                    }
                }

                var jwe = new JweDescriptor
                {
                    Payload = descriptor,
                    EncryptionKey = EncryptionKey,
                    EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256
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
                    //SigningCredentials = new SigningCredentials(WilsonSharedKey, SigningKey.Alg),
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.TryGetValue("exp", out var _) ? EpochTime.DateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.TryGetValue("iat", out var _) ? EpochTime.DateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
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

                descriptors.Add("JWT-" + payload.Key, descriptor);
            }

            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new SecurityTokenDescriptor()
                {
                    SigningCredentials = new SigningCredentials(WilsonSharedKey, ((SignatureAlgorithm)SigningKey.Alg!).Name),
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.TryGetValue("exp", out var _) ? EpochTime.DateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.TryGetValue("iat", out var _) ? EpochTime.DateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
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
                    SigningCredentials = new SigningCredentials(WilsonSharedKey, ((SignatureAlgorithm)SigningKey.Alg!).Name),
                    EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(EncryptionKey.K.ToArray()), KeyManagementAlgorithm.Aes128KW.Name, EncryptionAlgorithm.Aes128CbcHmacSha256.Name),
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.TryGetValue("exp", out var _) ? EpochTime.DateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.TryGetValue("iat", out var _) ? EpochTime.DateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
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

            foreach (var type in new[] { "JWE", "JWS", "JWT" })
            {
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

                    descriptors.Add(type + "-" + payload.Key, descriptor);
                }
            }

            return descriptors;
        }
    }
}