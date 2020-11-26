using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;

namespace JsonWebToken.Tests
{
    public class TokenFixture : IDisposable
    {
        private readonly KeyFixture _keyFixture;

        public IDictionary<string, string> ValidTokens { get; }
        public IDictionary<string, byte[]> ValidBinaryTokens { get; }
        public IEnumerable<TokenState> InvalidTokens { get; }
        public IDictionary<string, Dictionary<string, object>> Payloads { get; }
        public IDictionary<string, JwtDescriptor> Descriptors { get; }

        public TokenFixture()
        {
            _keyFixture = new KeyFixture();
            var signingKey = _keyFixture.SigningKey;
            var encryptionKey = _keyFixture.EncryptionKey;
            var payloads = CreatePayloads();
            var descriptors = CreateDescriptors(payloads, signingKey, encryptionKey);
            Descriptors = descriptors;
            ValidTokens = CreateTokens(descriptors);
            ValidBinaryTokens = CreateBinaryTokens(ValidTokens);
            InvalidTokens = CreateInvalidToken(signingKey, payloads["small"]);
            Payloads = payloads;
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

        private static IDictionary<string, Dictionary<string, object>> CreatePayloads()
        {
            byte[] bigData = new byte[1024 * 128];
            using (var rnd = RandomNumberGenerator.Create())
            {
                rnd.GetNonZeroBytes(bigData);
            }

            var payloads = new Dictionary<string, Dictionary<string, object>>
            {
                {
                    "empty", new Dictionary<string, object>()
                },
                {
                    "small", new Dictionary<string, object>
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
                    "multiAud", new Dictionary<string, object>
                    {
                        { "jti", "756E69717565206964656E746966696572"},
                        { "iss", "https://idp.example.com/"},
                        { "iat", 1508184845},
                        { "aud", new JArray("636C69656E745F6964", "X", "Y" ) },
                        { "exp", 1628184845},
                        { "nbf",  1508184845}
                    }
                },
                {
                    "nd-nbf", new Dictionary<string, object>
                    {
                        { "jti", "756E69717565206964656E746966696572"},
                        { "iss", "https://idp.example.com/"},
                        { "iat", 1508184845},
                        { "aud", "636C69656E745F6964"},
                        { "exp", 1628184845}
                    }
                },
                {
                    "medium", new Dictionary<string, object>
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
                    "big", new Dictionary<string, object>
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

        private static IDictionary<string, JwtDescriptor> CreateDescriptors(IDictionary<string, Dictionary<string, object>> payloads, SymmetricJwk signingKey, SymmetricJwk encryptionKey)
        {
            var descriptors = new Dictionary<string, JwtDescriptor>();
            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None);

                FillPayload(payload, descriptor);
                descriptors.Add("JWT-" + payload.Key, descriptor);
            }


            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor(signingKey, signingKey.SignatureAlgorithm);

                FillPayload(payload, descriptor);
                descriptors.Add("JWS-" + payload.Key, descriptor);
            }

            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor(signingKey, signingKey.SignatureAlgorithm);

                FillPayload(payload, descriptor);

                var jwe = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.A128KW, EncryptionAlgorithm.A128CbcHS256)
                {
                    Payload = descriptor,
                    Header = new JwtHeader
                    {
                        {"cty", "JWT" }
                    }
                };

                descriptors.Add("JWE-" + payload.Key, jwe);
            }

            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor(signingKey, signingKey.SignatureAlgorithm);

                FillPayload(payload, descriptor);

                var jwe = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.A128KW, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def)
                {
                    Payload = descriptor,
                    Header = new JwtHeader
                    {
                        {"cty", "JWT" }
                    }
                };

                descriptors.Add("JWE-DEF-" + payload.Key, jwe);
            }

            return descriptors;
        }

        private static void FillPayload(KeyValuePair<string, Dictionary<string, object>> payload, JwsDescriptor descriptor)
        {
            foreach (var property in payload.Value)
            {
                switch (property.Key)
                {
                    case "iat":
                    case "nbf":
                    case "exp":
                        if (property.Value is int intValue)
                        {
                            descriptor.Payload.Add(property.Key, intValue);
                        }
                        else
                        {
                            descriptor.Payload.Add(property.Key, (long)property.Value);
                        }
                        break;
                    default:
                        if (property.Value is JArray)
                        {
                            var array = new List<string>(((JArray)property.Value).ToObject<string[]>());
                            descriptor.Payload.Add("aud", array);
                        }
                        else
                        {
                            descriptor.Payload.Add(property.Key, (string)property.Value);
                        }
                        break;
                }
            }
        }

        private static IDictionary<string, string> CreateTokens(IDictionary<string, JwtDescriptor> descriptors)
        {
            var writer = new JwtWriter();
            return descriptors.ToDictionary(k => k.Key, k => writer.WriteTokenString(k.Value));
        }

        private static IList<TokenState> CreateInvalidToken(Jwk key, Dictionary<string, object> json)
        {
            var invalidTokens = new List<TokenState>();

            var payload = CreateJws(key, json, TokenValidationStatus.Expired);
            var token = CreateInvalidToken(TokenValidationStatus.Expired, payload);
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.InvalidClaim, "aud");
            payload.Payload.Add("aud", new List<string>(new[] { "X", "Y", "Z" }));
            token = CreateInvalidToken(TokenValidationStatus.InvalidClaim, payload, "aud");
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.InvalidClaim, "aud");
            token = CreateInvalidToken(TokenValidationStatus.InvalidClaim, payload, "aud");
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.InvalidClaim, "iss");
            token = CreateInvalidToken(TokenValidationStatus.InvalidClaim, payload, "iss");
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.MissingClaim, "aud");
            token = CreateInvalidToken(TokenValidationStatus.MissingClaim, payload, "aud");
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.MissingClaim, "iss");
            token = CreateInvalidToken(TokenValidationStatus.MissingClaim, payload, "iss");
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.MissingClaim, "exp");
            token = CreateInvalidToken(TokenValidationStatus.MissingClaim, payload, "exp");
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NotYetValid);
            token = CreateInvalidToken(TokenValidationStatus.NotYetValid, payload);
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NoError);
            token = CreateInvalidToken(TokenValidationStatus.InvalidSignature, payload);
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NoError);
            token = CreateInvalidToken(TokenValidationStatus.MalformedSignature, payload);
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NoError);
            token = CreateInvalidToken(TokenValidationStatus.MalformedToken, payload);
            invalidTokens.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NoError);
            token = CreateInvalidToken(TokenValidationStatus.MissingSignature, payload);
            invalidTokens.Add(token);

            return invalidTokens;
        }

        private static JwsDescriptor CreateJws(Jwk signingKey, Dictionary<string, object> descriptor, TokenValidationStatus status, string claim = null)
        {
            var payload = new JwtPayload();
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

            var d = new JwsDescriptor(signingKey, signingKey.SignatureAlgorithm);
            d.Payload = payload;
            return d;
        }

        private static TokenState CreateInvalidToken(TokenValidationStatus status, JwsDescriptor descriptor, string claim = null)
        {
            switch (status)
            {
                case TokenValidationStatus.SignatureKeyNotFound:
                    descriptor.Header.Add("kid", "X");
                    break;
                case TokenValidationStatus.MissingEncryptionAlgorithm:
                    descriptor.Header.Add("enc", (object)null);
                    break;
            }

            var token = descriptor;
            var writer = new JwtWriter();
            //writer.IgnoreTokenValidation = true;
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

        public void Dispose()
        {
            _keyFixture.Dispose();
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