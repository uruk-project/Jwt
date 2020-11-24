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
        public static readonly JwtDecoder JwtDotNetDecoder = new JwtDecoder(serializer, new JwtValidator(serializer, dateTimeProvider), urlEncoder, algorithm);

        public static readonly JwtSecurityTokenHandler Handler = new JwtSecurityTokenHandler();
        public static readonly JsonWebTokenHandler Handler2 = new JsonWebTokenHandler();

        public static readonly SigningCredentials signingCredentials = new SigningCredentials(JsonWebKey.Create(Tokens.SigningKey.ToString()), Tokens.SigningKey.SignatureAlgorithm!.Name.ToString());
        public static readonly EncryptingCredentials encryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(Tokens.EncryptionKey.ToArray()), "A128KW", "A128CBC-HS256");

        public static readonly JwtWriter Writer = new JwtWriter() { EnableHeaderCaching = true };


        private static readonly FixedSizedBufferWriter _output = new FixedSizedBufferWriter(8192);

        static WriteToken()
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }

        public abstract byte[] JsonWebToken(BenchmarkPayload payload);

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
            return Handler2.CreateToken(payload);
        }

        protected string WilsonJwsCore(string payload)
        {
            return Handler2.CreateToken(payload, signingCredentials);
        }

        protected string WilsonJweCore(string payload)
        {
            return Handler2.CreateToken(payload, signingCredentials, encryptingCredentials);
        }

        protected string WilsonJweCompressedCore(string payload)
        {
            return Handler2.CreateToken(payload, signingCredentials, encryptingCredentials, "DEF");
        }

        public abstract string jose_jwt(BenchmarkPayload payload);

        protected string JoseDotNetJwsCore(Dictionary<string, object> payload)
        {
            return Jose.JWT.Encode(payload, SigningKeyArray, JwsAlgorithm.HS256);
        }

        protected string JoseDotNetJweCore(Dictionary<string, object> payload)
        {
            var value = Jose.JWT.Encode(payload, SigningKeyArray, JwsAlgorithm.HS256);
            return Jose.JWT.Encode(value, EncryptionKeyArray, JweAlgorithm.A128KW, JweEncryption.A128CBC_HS256);
        }

        protected string JoseDotNetJweCompressedCore(Dictionary<string, object> payload)
        {
            var value = Jose.JWT.Encode(payload, SigningKeyArray, JwsAlgorithm.HS256);
            return Jose.JWT.Encode(value, EncryptionKeyArray, JweAlgorithm.A128KW, JweEncryption.A128CBC_HS256, JweCompression.DEF);
        }

        public abstract string Jwt_Net(BenchmarkPayload payload);

        protected string JwtDotNetJwsCore(Dictionary<string, object> payload)
        {
            return JwtDotNetEncoder.Encode(payload, SigningKeyArray);
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
            WilsonJwtDescriptor = Tokens.Payloads[name.Substring(name.LastIndexOf('6') - 1).Trim().Substring(0, 1)].ToString();
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
                var descriptor = new JwsDescriptor(SigningKey, SignatureAlgorithm.HmacSha256);

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            descriptor.Payload!.Add(property.Name, (long)property.Value);
                            break;
                        default:
                            descriptor.Payload!.Add(property.Name, (string)property.Value);
                            break;
                    }
                }

                descriptors.Add("JWT " + payload.Key + "6 claims", descriptor);
            }

            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new JwsDescriptor(SigningKey, SignatureAlgorithm.HmacSha256);

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            descriptor.Payload!.Add(property.Name, (long)property.Value);
                            break;
                        default:
                            descriptor.Payload!.Add(property.Name, (string)property.Value);
                            break;
                    }
                }

                descriptors.Add("JWS " + payload.Key + "6 claims", descriptor);
            }

            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new JwsDescriptor(SigningKey, SignatureAlgorithm.HmacSha256);

                foreach (var property in payload.Value.Properties())
                {
                    switch (property.Name)
                    {
                        case "iat":
                        case "nbf":
                        case "exp":
                            descriptor.Payload!.Add(property.Name, (long)property.Value);
                            break;
                        default:
                            descriptor.Payload!.Add(property.Name, (string)property.Value);
                            break;
                    }
                }

                var jwe = new JweDescriptor(EncryptionKey, KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256)
                {
                    Payload = descriptor,
                };

                descriptors.Add("JWE " + payload.Key + "6 claims", jwe);

                var jwec = new JweDescriptor(EncryptionKey, KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, CompressionAlgorithm.Deflate)
                {
                    Payload = descriptor
                };
                descriptors.Add("JWE DEF " + payload.Key + "6 claims", jwec);
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
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.TryGetValue("exp", out var _) ? EpochTime.ToDateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.TryGetValue("iat", out var _) ? EpochTime.ToDateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
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

                descriptors.Add("JWT " + payload.Key + "6 claims", descriptor);
            }

            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new SecurityTokenDescriptor()
                {
                    SigningCredentials = new SigningCredentials(WilsonSharedKey, SigningKey.SignatureAlgorithm!.Name.ToString()),
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.TryGetValue("exp", out var _) ? EpochTime.ToDateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.TryGetValue("iat", out var _) ? EpochTime.ToDateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
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

                descriptors.Add("JWS " + payload.Key + "6 claims", descriptor);
            }

            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new SecurityTokenDescriptor()
                {
                    SigningCredentials = new SigningCredentials(WilsonSharedKey, SigningKey.SignatureAlgorithm!.Name.ToString()),
                    EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(EncryptionKey.K.ToArray()), KeyManagementAlgorithm.Aes128KW.Name.ToString(), EncryptionAlgorithm.Aes128CbcHmacSha256.Name.ToString()),
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.TryGetValue("exp", out var _) ? EpochTime.ToDateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.TryGetValue("iat", out var _) ? EpochTime.ToDateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
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

                descriptors.Add("JWE " + payload.Key + "6 claims", descriptor);
            }

            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new SecurityTokenDescriptor()
                {
                    SigningCredentials = new SigningCredentials(WilsonSharedKey, SigningKey.SignatureAlgorithm!.Name.ToString()),
                    EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(EncryptionKey.K.ToArray()), KeyManagementAlgorithm.Aes128KW.Name.ToString(), EncryptionAlgorithm.Aes128CbcHmacSha256.Name.ToString()),
                    Subject = new ClaimsIdentity(),
                    Expires = payload.Value.TryGetValue("exp", out var _) ? EpochTime.ToDateTime(payload.Value.Value<long>("exp")) : default(DateTime?),
                    IssuedAt = payload.Value.TryGetValue("iat", out var _) ? EpochTime.ToDateTime(payload.Value.Value<long>("iat")) : default(DateTime?),
                    CompressionAlgorithm = "DEF"
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

                descriptors.Add("JWE DEF " + payload.Key + "6 claims", descriptor);
            }

            return descriptors;
        }

        private static Dictionary<string, Dictionary<string, object>> CreateDictionaryDescriptors()
        {
            var descriptors = new Dictionary<string, Dictionary<string, object>>();

            foreach (var type in new[] { "JWE", "JWS", "JWT", "JWE DEF" })
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

                    descriptors.Add(type + " " + payload.Key + "6 claims", descriptor);
                }
            }

            return descriptors;
        }
    }
}