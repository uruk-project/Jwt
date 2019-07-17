using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken.Performance
{
    public static class Tokens
    {
        public static IDictionary<string, string> ValidTokens { get; }
        public static IDictionary<string, byte[]> ValidBinaryTokens { get; }
        public static IEnumerable<TokenState> InvalidTokens { get; }

        public static SymmetricJwk SigningKey { get; }

        public static SymmetricJwk EncryptionKey { get; }

        public static IDictionary<string, JObject> Payloads { get; }

        public static IDictionary<string, JwtDescriptor> Descriptors { get; }

        static Tokens()
        {
            var signingKey = CreateSigningKey();
            var encryptionKey = CreateEncryptionKey();
            var payloads = CreatePayloads();
            var descriptors = CreateDescriptors(payloads, signingKey, encryptionKey);
            Descriptors = descriptors;
            ValidTokens = CreateTokens(descriptors);
            ValidBinaryTokens = CreateBinaryTokens(ValidTokens);
            InvalidTokens = CreateInvalidToken(signingKey, payloads["small"]);
            Payloads = payloads;
            SigningKey = signingKey;
            EncryptionKey = encryptionKey;
        }

        private static IDictionary<string, byte[]> CreateBinaryTokens(IDictionary<string, string> validTokens)
        {
            var result = new Dictionary<string, byte[]>();
            foreach (var item in validTokens)
            {
                result.Add(item.Key, Encoding.UTF8.GetBytes(item.Value));
            }

            return result;
        }

        private static SymmetricJwk CreateSigningKey()
        {
            return SymmetricJwk.GenerateKey(128, SignatureAlgorithm.HmacSha256);
        }

        private static SymmetricJwk CreateEncryptionKey()
        {
            return SymmetricJwk.GenerateKey(128, KeyManagementAlgorithm.Aes128KW);
        }

        private static IDictionary<string, JObject> CreatePayloads()
        {
            byte[] bigData = new byte[1024 * 128];
            using (var rnd = RandomNumberGenerator.Create())
            {
                rnd.GetNonZeroBytes(bigData);
            }

            var payloads = new Dictionary<string, JObject>
            {
                {
                    "empty", new JObject()
                },
                {
                    "small", new JObject
                    {
                        { "jti", "756E69717565206964656E746966696572"},
                        { "iss", "https://idp.example.com/"},
                        { "iat", 1508184845},
                        { "aud", "636C69656E745F6964"},
                        { "exp", 1628184845},
                        { "nbf",  1508184845}
                    }
                },
                {
                    "medium", new JObject
                    {
                        { "jti", "756E69717565206964656E746966696572"},
                        { "iss", "https://idp.example.com/"},
                        { "iat", 1508184845},
                        { "aud", "636C69656E745F6964"},
                        { "exp", 1628184845},
                        { "nbf",  1508184845},
                        { "claim1", "value1ABCDEFGH" },
                        { "claim2", "value1ABCDEFGH" },
                        { "claim3", "value1ABCDEFGH" },
                        { "claim4", "value1ABCDEFGH" },
                        { "claim5", "value1ABCDEFGH" },
                        { "claim6", "value1ABCDEFGH" },
                        { "claim7", "value1ABCDEFGH" },
                        { "claim8", "value1ABCDEFGH" },
                        { "claim9", "value1ABCDEFGH" },
                        { "claim10", "value1ABCDEFGH" },
                        { "claim11", "value1ABCDEFGH" },
                        { "claim12", "value1ABCDEFGH" },
                        { "claim13", "value1ABCDEFGH" },
                        { "claim14", "value1ABCDEFGH" },
                        { "claim15", "value1ABCDEFGH" },
                        { "claim16", "value1ABCDEFGH" }
                    }
                },
                {
                    "big", new JObject
                    {
                        { "jti", "756E69717565206964656E746966696572" },
                        { "iss", "https://idp.example.com/" },
                        { "iat", 1508184845 },
                        { "aud", "636C69656E745F6964" },
                        { "exp", 1628184845 },
                        { "nbf",  1508184845},
                        { "big_claim", Convert.ToBase64String(bigData) }
                    }
                },
            };

            return payloads;
        }

        private static IDictionary<string, JwtDescriptor> CreateDescriptors(IDictionary<string, JObject> payloads, SymmetricJwk signingKey, SymmetricJwk encryptionKey)
        {
            var descriptors = new Dictionary<string, JwtDescriptor>();
            foreach (var payload in payloads)
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
                            descriptor.AddClaim(property.Name, EpochTime.ToDateTime((long)property.Value));
                            break;
                        default:
                            descriptor.AddClaim(property.Name, (string)property.Value);
                            break;
                    }
                }

                descriptors.Add("JWT-" + payload.Key, descriptor);
            }


            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    SigningKey = signingKey,
                    Algorithm = (SignatureAlgorithm)signingKey.Alg
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

            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    SigningKey = signingKey,
                    Algorithm = (SignatureAlgorithm)signingKey.Alg
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
                    EncryptionKey = encryptionKey,
                    EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256,
                    Algorithm = KeyManagementAlgorithm.Aes128KW,
                    ContentType = "JWT"
                };

                descriptors.Add("JWE-" + payload.Key, jwe);
            }

            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    SigningKey = signingKey,
                    Algorithm = (SignatureAlgorithm)signingKey.Alg
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
                    EncryptionKey = encryptionKey,
                    EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256,
                    Algorithm = KeyManagementAlgorithm.Aes128KW,
                    ContentType = "JWT",
                    CompressionAlgorithm = CompressionAlgorithm.Deflate
                };

                descriptors.Add("JWE-DEF-" + payload.Key, jwe);
            }

            return descriptors;
        }

        private static IDictionary<string, string> CreateTokens(IDictionary<string, JwtDescriptor> descriptors)
        {
            var writer = new JwtWriter();
            return descriptors.ToDictionary(k => k.Key, k => writer.WriteTokenString(k.Value));
        }

        private static IList<TokenState> CreateInvalidToken(Jwk key, JObject json)
        {
            var jwts = new List<TokenState>();

            var payload = CreateJws(json, TokenValidationStatus.Expired);
            var token = CreateInvalidToken(key, TokenValidationStatus.Expired, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.InvalidClaim, "aud");
            token = CreateInvalidToken(key, TokenValidationStatus.InvalidClaim, payload, "aud");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.InvalidClaim, "iss");
            token = CreateInvalidToken(key, TokenValidationStatus.InvalidClaim, payload, "iss");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.MissingClaim, "aud");
            token = CreateInvalidToken(key, TokenValidationStatus.MissingClaim, payload, "aud");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.MissingClaim, "iss");
            token = CreateInvalidToken(key, TokenValidationStatus.MissingClaim, payload, "iss");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.MissingClaim, "exp");
            token = CreateInvalidToken(key, TokenValidationStatus.MissingClaim, payload, "exp");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.NotYetValid);
            token = CreateInvalidToken(key, TokenValidationStatus.NotYetValid, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.Success);
            token = CreateInvalidToken(key, TokenValidationStatus.InvalidSignature, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.Success);
            token = CreateInvalidToken(key, TokenValidationStatus.MalformedSignature, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.Success);
            token = CreateInvalidToken(key, TokenValidationStatus.MalformedToken, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.Success);
            token = CreateInvalidToken(key, TokenValidationStatus.MissingSignature, payload);
            jwts.Add(token);

            return jwts;
        }

        private static JwsDescriptor CreateJws(JObject descriptor, TokenValidationStatus status, string claim = null)
        {
            var payload = new JObject();
            foreach (var kvp in descriptor)
            {
                switch (status)
                {
                    case TokenValidationStatus.InvalidClaim:
                        if (kvp.Key == "aud" && claim == "aud")
                        {
                            payload.Add(kvp.Key, kvp.Value + "XXX");
                            continue;
                        }
                        if (kvp.Key == "iss" && claim == "iss")
                        {
                            payload.Add(kvp.Key, kvp.Value + "XXX");
                            continue;
                        }
                        break;
                    case TokenValidationStatus.MissingClaim:
                        if (kvp.Key == "exp" & claim == "exp")
                        {
                            continue;
                        }
                        if (kvp.Key == "aud" & claim == "aud")
                        {
                            continue;
                        }
                        if (kvp.Key == "iss" && claim == "iss")
                        {
                            continue;
                        }
                        break;
                    case TokenValidationStatus.Expired:
                        if (kvp.Key == "exp")
                        {
                            payload.Add(kvp.Key, 1500000000);
                            continue;
                        }
                        if (kvp.Key == "nbf")
                        {
                            payload.Add(kvp.Key, 1400000000);
                            continue;
                        }
                        break;
                    case TokenValidationStatus.NotYetValid:
                        if (kvp.Key == "exp")
                        {
                            payload.Add(kvp.Key, 2100000000);
                            continue;
                        }
                        if (kvp.Key == "nbf")
                        {
                            payload.Add(kvp.Key, 2000000000);
                            continue;
                        }
                        break;
                }

                payload.Add(kvp.Key, kvp.Value);
            }

            return new JwsDescriptor(new JwtObject(), ToJwtObject(payload));
        }

        private static TokenState CreateInvalidToken(TokenValidationStatus status, JwtDescriptor descriptor, string claim = null)
        {
            switch (status)
            {
                case TokenValidationStatus.SignatureKeyNotFound:
                    descriptor.Header.Replace(new JwtProperty(HeaderParameters.KidUtf8, (string)descriptor.Header[HeaderParameters.KidUtf8].Value + "x"));
                    break;
                case TokenValidationStatus.MissingEncryptionAlgorithm:
                    descriptor.Header.Replace(new JwtProperty(HeaderParameters.EncUtf8));
                    break;
            }

            var token = descriptor;
            var writer = new JwtWriter();
            writer.IgnoreTokenValidation = true;
            var jwt = writer.WriteTokenString(token);

            switch (status)
            {
                case TokenValidationStatus.MalformedToken:
                    jwt = "/" + jwt.Substring(0, jwt.Length - 1);
                    break;
                case TokenValidationStatus.InvalidSignature:
                    var parts = jwt.Split('.');
                    parts[2] = new string(parts[2].Reverse().ToArray());
                    jwt = parts[0] + "." + parts[1] + "." + parts[2];
                    break;
                case TokenValidationStatus.MalformedSignature:
                    jwt = jwt.Substring(0, jwt.Length - 2);
                    break;
                case TokenValidationStatus.MissingSignature:
                    parts = jwt.Split('.');
                    jwt = parts[0] + "." + parts[1] + ".";
                    break;
                default:
                    break;
            }

            return new TokenState(jwt, status);
        }

        private static TokenState CreateInvalidToken(Jwk signingKey, TokenValidationStatus status, JwsDescriptor descriptor, string claim = null)
        {
            descriptor.SigningKey = signingKey;
            descriptor.Algorithm = (SignatureAlgorithm)signingKey.Alg;

            return CreateInvalidToken(status, descriptor);
        }

        private static TokenState CreateInvalidToken(Jwk signingKey, Jwk encryptionKey, TokenValidationStatus status, JweDescriptor descriptor, string claim = null)
        {
            descriptor.Payload.SigningKey = SigningKey;
            descriptor.EncryptionKey = encryptionKey;
            descriptor.EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256;

            return CreateInvalidToken(status, descriptor);
        }

        public static JwtObject ToJwtObject(JObject json)
        {
            var jwtObject = new JwtObject();
            foreach (var property in json.Properties())
            {
                JwtProperty jwtProperty;
                switch (property.Value.Type)
                {
                    case JTokenType.Object:
                        jwtProperty = new JwtProperty(property.Name, ToJwtObject(property.Value.Value<JObject>()));
                        break;
                    case JTokenType.Array:
                        jwtProperty = new JwtProperty(property.Name, ToJwtArray(property.Value.Value<JArray>()));
                        break;
                    case JTokenType.Integer:
                        jwtProperty = new JwtProperty(property.Name, property.Value.Value<long>());
                        break;
                    case JTokenType.Float:
                        jwtProperty = new JwtProperty(property.Name, property.Value.Value<double>());
                        break;
                    case JTokenType.String:
                        jwtProperty = new JwtProperty(property.Name, property.Value.Value<string>());
                        break;
                    case JTokenType.Boolean:
                        jwtProperty = new JwtProperty(property.Name, property.Value.Value<bool>());
                        break;
                    case JTokenType.Null:
                        jwtProperty = new JwtProperty(property.Name);
                        break;
                    default:
                        throw new NotSupportedException();
                }

                jwtObject.Add(jwtProperty);
            }

            return jwtObject;
        }

        private static JwtArray ToJwtArray(JArray array)
        {
            var list = new List<JwtValue>(array.Count);
            for (int i = 0; i < array.Count; i++)
            {
                var value = array[i];
                switch (value.Type)
                {
                    case JTokenType.Object:
                        list.Add(new JwtValue(ToJwtObject((JObject)value)));
                        break;
                    case JTokenType.Array:
                        list.Add(new JwtValue(ToJwtArray((JArray)value)));
                        break;
                    case JTokenType.Integer:
                        list.Add(new JwtValue((long)value));
                        break;
                    case JTokenType.Float:
                        list.Add(new JwtValue((double)value));
                        break;
                    case JTokenType.String:
                        list.Add(new JwtValue((string)value));
                        break;
                    case JTokenType.Boolean:
                        list.Add(new JwtValue((bool)value));
                        break;
                    case JTokenType.Null:
                        list.Add(new JwtValue());
                        break;
                    default:
                        throw new NotSupportedException();
                }
            }

            return new JwtArray(list);
        }
    }

    public class TokenState
    {
        public TokenState(string jwt, TokenValidationStatus status)
        {
            Jwt = jwt;
            Status = status;
        }

        public string Jwt { get; }
        public TokenValidationStatus Status { get; }
    }
}