using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;

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
            InvalidTokens = CreateInvalidToken(signingKey, payloads["0"]);
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
            return SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256);
        }

        private static SymmetricJwk CreateEncryptionKey()
        {
            return SymmetricJwk.GenerateKey(KeyManagementAlgorithm.Aes128KW);
        }

        private static IDictionary<string, JObject> CreatePayloads()
        {
            var payloads = new Dictionary<string, JObject>();

            for (int i = 0; i < 10; i++)
            {
                var payload = new JObject
                {
                    { "jti", "756E69717565206964656E746966696572"},
                    { "iss", "https://idp.example.com/"},
                    { "iat", 1508184845},
                    { "aud", "636C69656E745F6964"},
                    { "exp", 1628184845},
                    { "nbf",  1508184845}
                };
                const int intValue = 1508184845;
                const string stringValue = "636C69656E745F6964";
                for (int j = 0; j < i * 10; j++)
                {
                    if (j % 2 == 0)
                    {
                        payload.Add("prop" + j, intValue);
                    }
                    else
                    {
                        payload.Add("prop" + j, stringValue);
                    }
                }

                payloads.Add(i.ToString(), payload);
            }

            return payloads;
        }

        private static IDictionary<string, JwtDescriptor> CreateDescriptors(IDictionary<string, JObject> payloads, SymmetricJwk signingKey, SymmetricJwk encryptionKey)
        {
            var descriptors = new Dictionary<string, JwtDescriptor>();
            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None);

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

                descriptors.Add("JWT " + (payload.Key == "0" ? "" : payload.Key) + "6 claims", descriptor);
            }

            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HmacSha256);

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

                descriptors.Add("JWS " + (payload.Key == "0" ? "" : payload.Key) + "6 claims", descriptor);
            }

            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HmacSha256);

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

                var jwe = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256)
                {
                    Payload = descriptor,
                    Header = new JwtHeader
                    {
                        { "cty", "JWT" }
                    }
                };

                descriptors.Add("JWE " + (payload.Key == "0" ? "" : payload.Key) + "6 claims", jwe);
            }

            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HmacSha256);

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

                var jwe = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, CompressionAlgorithm.Deflate)
                {
                    Payload = descriptor,
                    Header = new JwtHeader
                    {
                        { "cty", "JWT" }
                    }
                };

                descriptors.Add("JWE DEF " + (payload.Key == "0" ? "" : payload.Key) + "6 claims", jwe);
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

            var payload = CreateJws(key, json, TokenValidationStatus.Expired);
            var token = CreateInvalidToken(TokenValidationStatus.Expired, payload);
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.InvalidClaim, "aud");
            token = CreateInvalidToken(TokenValidationStatus.InvalidClaim, payload, "aud");
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.InvalidClaim, "iss");
            token = CreateInvalidToken(TokenValidationStatus.InvalidClaim, payload, "iss");
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.MissingClaim, "aud");
            token = CreateInvalidToken(TokenValidationStatus.MissingClaim, payload, "aud");
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.MissingClaim, "iss");
            token = CreateInvalidToken(TokenValidationStatus.MissingClaim, payload, "iss");
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.MissingClaim, "exp");
            token = CreateInvalidToken(TokenValidationStatus.MissingClaim, payload, "exp");
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NotYetValid);
            token = CreateInvalidToken(TokenValidationStatus.NotYetValid, payload);
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NoError);
            token = CreateInvalidToken(TokenValidationStatus.InvalidSignature, payload);
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NoError);
            token = CreateInvalidToken(TokenValidationStatus.MalformedSignature, payload);
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NoError);
            token = CreateInvalidToken(TokenValidationStatus.MalformedToken, payload);
            jwts.Add(token);

            payload = CreateJws(key, json, TokenValidationStatus.NoError);
            token = CreateInvalidToken(TokenValidationStatus.MissingSignature, payload);
            jwts.Add(token);

            return jwts;
        }

        private static JwsDescriptor CreateJws(Jwk signingKey, JObject descriptor, TokenValidationStatus status, string? claim = null)
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


                switch (kvp.Value.Type)
                {
                    case JTokenType.Object:
                        payload.Add(kvp.Key, (object)kvp.Value);
                        break;
                    case JTokenType.Array:
                        payload.Add(kvp.Key, (object[])(object)kvp.Value);
                        break;
                    case JTokenType.Integer:
                        payload.Add(kvp.Key, (long)kvp.Value);
                        break;
                    case JTokenType.Float:
                        payload.Add(kvp.Key, (double)kvp.Value);
                        break;
                    case JTokenType.String:
                        payload.Add(kvp.Key, (string)kvp.Value);
                        break;
                    case JTokenType.Boolean:
                        payload.Add(kvp.Key, (bool)kvp.Value);
                        break;
                    case JTokenType.Null:
                        payload.Add(kvp.Key, (object)kvp.Value);
                        break;
                }
            }

            var d = new JwsDescriptor(signingKey, SignatureAlgorithm.HmacSha256);
            d.Payload = payload;
            return d;
        }

        private static TokenState CreateInvalidToken(TokenValidationStatus status, JwtDescriptor descriptor, string? claim = null)
        {
            switch (status)
            {
                case TokenValidationStatus.SignatureKeyNotFound:
                    descriptor.Header.Add(HeaderParameters.Kid, "x");
                    break;
                case TokenValidationStatus.MissingEncryptionAlgorithm:
                    descriptor.Header.Add(HeaderParameters.Enc, (object)null!);
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