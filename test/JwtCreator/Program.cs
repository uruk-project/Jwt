using JsonWebToken;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
//using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtCreator
{
    class Program
    {
        static void Main(string[] args)
        {
            var jwks = GenerateKeys();

            var location = typeof(Program).GetTypeInfo().Assembly.Location;
            var dirPath = Path.GetDirectoryName(location);
            var keysPath = Path.Combine(dirPath, "./jwks.json"); ;
            //var jwksString = File.ReadAllText(keysPath);
            //var jwks = new JsonWebKeySet(jwksString);

            var descriptorsPath = Path.Combine(dirPath, "./descriptors.json");
            var descriptorsString = File.ReadAllText(descriptorsPath);
            var descriptors = JArray.Parse(descriptorsString);

            var writer = new JsonWebTokenWriter();
            var result = new JArray();
            var json = descriptors.First() as JObject;


            foreach (var key in jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Sig))
            {
                var jwsDescriptor = new JwsDescriptor(json);
                jwsDescriptor.Key = key;
                var jwt = writer.WriteToken(jwsDescriptor);
                result.Add(jwt);
            }

            var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
            var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
            var issuer = "https://idp.example.com/";
            var audience = "636C69656E745F6964";
            //var jti = "756E69717565206964656E746966696572";
            var bigDescriptor = new JwsDescriptor()
            {
                IssuedAt = issuedAt,
                ExpirationTime = expires,
                Issuer = issuer,
                Audience = audience,
                Key = jwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig)
            };
            var data = new byte[1024 * 1024];
            RandomNumberGenerator.Fill(data);
            bigDescriptor.Payload["big_claim"] = Base64Url.Base64UrlEncode(data);
            var bigJwt = writer.WriteToken(bigDescriptor);
            result.Add(bigJwt);

            var signingKey = jwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
            var encryptionAlgorithms = new[] { ContentEncryptionAlgorithms.Aes128CbcHmacSha256, ContentEncryptionAlgorithms.Aes192CbcHmacSha384, ContentEncryptionAlgorithms.Aes256CbcHmacSha512 };
            foreach (var key in jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Enc))
            {
                foreach (var enc in encryptionAlgorithms)
                {
                    if (!key.IsSupportedAlgorithm(enc))
                    {
                        continue;
                    }

                    var jweDescriptor = new JweDescriptor(json);
                    jweDescriptor.Payload.Key = signingKey;
                    jweDescriptor.Key = key;
                    jweDescriptor.EncryptionAlgorithm = enc;
                    var jwt = writer.WriteToken(jweDescriptor);
                    result.Add(jwt);
                }
            }
            
            var invalidJwt = GenerateInvalidJwt(jwks, json);

            var jwtPath = Path.Combine(dirPath, "./jwts.json");
            var invalidJwtsPath = Path.Combine(dirPath, "./invalid_jwts.json");
            File.WriteAllText(jwtPath, result.ToString());
            File.WriteAllText(invalidJwtsPath, invalidJwt.ToString());
            File.WriteAllText(keysPath, jwks.ToString());
        }

        private static JArray GenerateInvalidJwt(JsonWebKeySet jwks, JObject json)
        {
            var jwts = new JArray();

            var payload = CreateJws(json, TokenValidationStatus.Expired);
            var token = CreateToken(jwks, TokenValidationStatus.Expired, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.InvalidClaim, "aud");
            token = CreateToken(jwks, TokenValidationStatus.InvalidClaim, payload, "aud");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.InvalidClaim, "iss");
            token = CreateToken(jwks, TokenValidationStatus.InvalidClaim, payload, "iss");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.MissingClaim, "aud");
            token = CreateToken(jwks, TokenValidationStatus.MissingClaim, payload, "aud");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.MissingClaim, "iss");
            token = CreateToken(jwks, TokenValidationStatus.MissingClaim, payload, "iss");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.MissingClaim, "exp");
            token = CreateToken(jwks, TokenValidationStatus.MissingClaim, payload, "exp");
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.NotYetValid);
            token = CreateToken(jwks, TokenValidationStatus.NotYetValid, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.Success);
            token = CreateToken(jwks, TokenValidationStatus.InvalidSignature, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.Success);
            token = CreateToken(jwks, TokenValidationStatus.MalformedSignature, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.Success);
            token = CreateToken(jwks, TokenValidationStatus.MalformedToken, payload);
            jwts.Add(token);

            payload = CreateJws(json, TokenValidationStatus.Success);
            token = CreateToken(jwks, TokenValidationStatus.MissingSignature, payload);
            jwts.Add(token);

            return jwts;
        }

        private static JweDescriptor CreateJwe(JObject descriptor, TokenValidationStatus status)
        {
            var payload = new JObject();
            foreach (var claim in descriptor)
            {
                switch (status)
                {
                    case TokenValidationStatus.MissingEncryptionAlgorithm:
                        break;
                    case TokenValidationStatus.DecryptionFailed:
                        break;
                    default:
                        break;
                }

                payload.Add(claim.Key, claim.Value);
            }

            return new JweDescriptor(payload);
        }

        private static JwsDescriptor CreateJws(JObject descriptor, TokenValidationStatus status, string claim = null)
        {
            var payload = new JObject();
            foreach (var kvp in descriptor)
            {
                switch (status)
                {
                    case TokenValidationStatus.MalformedToken:
                        break;
                    case TokenValidationStatus.InvalidSignature:
                        break;
                    case TokenValidationStatus.SignatureKeyNotFound:
                        break;
                    case TokenValidationStatus.MalformedSignature:
                        break;
                    case TokenValidationStatus.MissingSignature:
                        break;
                    case TokenValidationStatus.InvalidClaim:
                        if (kvp.Key == "aud" && claim =="aud")
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
                    case TokenValidationStatus.TokenReplayed:
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
                    case TokenValidationStatus.MissingEncryptionAlgorithm:
                        break;
                    case TokenValidationStatus.DecryptionFailed:
                        break;
                    default:
                        break;
                }

                payload.Add(kvp.Key, kvp.Value);
            }

            return new JwsDescriptor(payload);
        }

        private static JObject CreateToken(TokenValidationStatus status, JwtDescriptor descriptor, string claim = null)
        {
            switch (status)
            {
                case TokenValidationStatus.SignatureKeyNotFound:
                    descriptor.Header["kid"] += "x";
                    break;
                case TokenValidationStatus.MissingEncryptionAlgorithm:
                    descriptor.Header["enc"] = null;
                    break;
            }

            var token = descriptor;
            var writer = new JsonWebTokenWriter();
            var jwt = writer.WriteToken(token);

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

            var o = new JObject();
            o["jwt"] = jwt;
            o["status"] = status.ToString();
            if (claim != null)
            {
                o["claim"] = claim;
            }

            return o;
        }
        private static JObject CreateToken(JsonWebKeySet jwks, TokenValidationStatus status, JwsDescriptor descriptor, string claim = null)
        {
            var key = jwks.Keys.First(k => k.Use == "sig" && k.Alg == "HS256");
            var encKey = jwks.Keys.First(k => k.Use == "enc" && k.Alg == "dir");
            descriptor.Key = key;

            return CreateToken(status, descriptor);
        }

        private static JObject CreateToken(JsonWebKeySet jwks, TokenValidationStatus status, JweDescriptor descriptor, string claim = null)
        {
            var key = jwks.Keys.First(k => k.Use == "sig" && k.Alg == "HS256");
            var encKey = jwks.Keys.First(k => k.Use == "enc" && k.Alg == "dir");
            descriptor.Payload.Key = key;
            descriptor.Key = encKey;
            descriptor.EncryptionAlgorithm = ContentEncryptionAlgorithms.Aes128CbcHmacSha256;

            return CreateToken(status, descriptor);
        }

        private static JsonWebKeySet GenerateKeys()
        {
            var keys = new JsonWebKeySet();
            var hsKeySizes = new[] { 256, 384, 512 };
            var kwKeySizes = new[] { 128, 192, 256 };
            foreach (var keySize in hsKeySizes)
            {
                var key = SymmetricJwk.GenerateKey(keySize);
                key.Use = JsonWebKeyUseNames.Sig;
                key.Alg = "HS" + keySize;
                key.Kid = "symmetric-" + keySize;
                keys.Add(key);
            }

            foreach (var keySize in hsKeySizes)
            {
                var key = SymmetricJwk.GenerateKey(keySize);
                key.Use = JsonWebKeyUseNames.Enc;
                key.Alg = "dir";
                key.Kid = "dir-" + keySize;
                keys.Add(key);
            }

            foreach (var keySize in kwKeySizes)
            {
                var key = SymmetricJwk.GenerateKey(keySize);
                key.Use = JsonWebKeyUseNames.Enc;
                key.Alg = "A" + keySize + "KW";
                key.Kid = "kw-" + keySize;
                keys.Add(key);
            }

            var rsaKeySizes = new[] { 2048, 4096 };
            foreach (var hsKeySize in hsKeySizes)
            {
                foreach (var rsaKeySize in rsaKeySizes)
                {
                    var key = RsaJwk.GenerateKey(rsaKeySize, true);
                    key.Use = JsonWebKeyUseNames.Sig;
                    key.Alg = "RS" + hsKeySize;
                    key.Kid = "rsa-pkcs1-" + hsKeySize + "-" + rsaKeySize;
                    keys.Add(key);
                }
                foreach (var rsaKeySize in rsaKeySizes)
                {
                    var key = RsaJwk.GenerateKey(rsaKeySize, true);
                    key.Use = JsonWebKeyUseNames.Sig;
                    key.Alg = "PS" + hsKeySize;
                    key.Kid = "rsa-pss-" + hsKeySize + "-" + rsaKeySize;
                    keys.Add(key);
                }
            }

            foreach (var rsaKeySize in rsaKeySizes)
            {
                var key = RsaJwk.GenerateKey(rsaKeySize, true);
                key.Use = JsonWebKeyUseNames.Enc;
                key.Alg = "RSA1_5";
                key.Kid = "rsa1-5-" + rsaKeySize;
                keys.Add(key);

                key = RsaJwk.GenerateKey(rsaKeySize, true);
                key.Use = JsonWebKeyUseNames.Enc;
                key.Alg = "RSA-OAEP";
                key.Kid = "rsa-oaep-" + rsaKeySize;
                keys.Add(key);

                key = RsaJwk.GenerateKey(rsaKeySize, true);
                key.Use = JsonWebKeyUseNames.Enc;
                key.Alg = "RSA-OAEP-256";
                key.Kid = "rsa-oaep-256-" + rsaKeySize;
                keys.Add(key);
            }

            var esKey = EcdsaJwk.GenerateKey(JsonWebKeyECTypes.P256, true);
            esKey.Use = JsonWebKeyUseNames.Sig;
            esKey.Alg = "ES256";
            esKey.Kid = "ecdsa-" + esKey.KeySize;
            keys.Add(esKey);

            esKey = EcdsaJwk.GenerateKey(JsonWebKeyECTypes.P384, true);
            esKey.Use = JsonWebKeyUseNames.Sig;
            esKey.Alg = "ES384";
            esKey.Kid = "ecdsa-" + esKey.KeySize;
            keys.Add(esKey);

            esKey = EcdsaJwk.GenerateKey(JsonWebKeyECTypes.P521, true);
            esKey.Use = JsonWebKeyUseNames.Sig;
            esKey.Alg = "ES512";
            esKey.Kid = "ecdsa-" + esKey.KeySize;
            keys.Add(esKey);

            return keys;
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
}