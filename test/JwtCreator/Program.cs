using JsonWebToken;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtCreator
{
    class Program
    {
        static void Main(string[] args)
        {
            var jwks = GenerateKeys();

            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
            var location = typeof(Program).GetTypeInfo().Assembly.Location;
            var dirPath = Path.GetDirectoryName(location);
            var keysPath = Path.Combine(dirPath, "./jwks.json"); ;
            //var jwksString = File.ReadAllText(keysPath);
            //var jwks = new JsonWebKeySet(jwksString);

            var descriptorsPath = Path.Combine(dirPath, "./descriptors.json");
            var descriptorsString = File.ReadAllText(descriptorsPath);
            var descriptors = JArray.Parse(descriptorsString).Select(t => new JsonWebTokenDescriptor(t.ToString()));

            var handler = new JwtSecurityTokenHandler();
            var result = new JArray();
            var descriptor = descriptors.First();
            foreach (var key in jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Sig))
            {
                if (key.Alg.StartsWith("PS"))
                {
                    continue;
                }

                var payload = new System.IdentityModel.Tokens.Jwt.JwtPayload();
                var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(new Microsoft.IdentityModel.Tokens.JsonWebKey(key.ToString()), key.Alg);
                var header = new System.IdentityModel.Tokens.Jwt.JwtHeader(signingCredentials);
                header.Remove("typ");
                foreach (var claim in descriptor.Payload)
                {
                    payload.Add(claim.Key, claim.Value);
                }

                var token = new JwtSecurityToken(header, payload);
                var jwt = handler.WriteToken(token);
                result.Add(jwt);
            }

            var encryptionAlgorithms = new[] { SecurityAlgorithms.Aes128CbcHmacSha256, SecurityAlgorithms.Aes192CbcHmacSha384, SecurityAlgorithms.Aes256CbcHmacSha512 };
            foreach (var key in jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Enc))
            {
                foreach (var enc in encryptionAlgorithms)
                {
                    var payload = new System.IdentityModel.Tokens.Jwt.JwtPayload();
                    var signingKey = jwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
                    var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(new Microsoft.IdentityModel.Tokens.JsonWebKey(signingKey.ToString()), signingKey.Alg);
                    var header = new System.IdentityModel.Tokens.Jwt.JwtHeader(signingCredentials);
                    header.Remove("typ");
                    var token = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor();
                    token.SigningCredentials = signingCredentials;
                    var encryptionCredentials = new Microsoft.IdentityModel.Tokens.EncryptingCredentials(new Microsoft.IdentityModel.Tokens.JsonWebKey(key.ToString()), key.Alg, enc);
                    token.EncryptingCredentials = encryptionCredentials;
                    token.Subject = new ClaimsIdentity();
                    foreach (var claim in descriptor.Payload)
                    {
                        token.Subject.AddClaim(new Claim(claim.Key, claim.Value.ToString()));
                    }

                    token.Expires = DateTime.UtcNow.AddYears(10);
                    try
                    {
                        var jwt = handler.CreateEncodedJwt(token);
                        result.Add(jwt);
                    }
                    catch (Exception e)
                    {
                    }
                }
            }

            var invalidJwt = GenerateInvalidJwt(jwks, descriptor);

            var jwtPath = Path.Combine(dirPath, "./jwts.json");
            var invalidJwtsPath = Path.Combine(dirPath, "./invalid_jwts.json");
            File.WriteAllText(jwtPath, result.ToString());
            File.WriteAllText(invalidJwtsPath, invalidJwt.ToString());
            File.WriteAllText(keysPath, jwks.ToString());
        }

        private static JArray GenerateInvalidJwt(JsonWebKeySet jwks, JsonWebTokenDescriptor descriptor)
        {
            var jwts = new JArray();

            var payload = CreatePayload(descriptor, TokenValidationStatus.Expired);
            var token = CreateToken(jwks, TokenValidationStatus.Expired, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.InvalidAudience);
            token = CreateToken(jwks, TokenValidationStatus.InvalidAudience, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.InvalidIssuer);
            token = CreateToken(jwks, TokenValidationStatus.InvalidIssuer, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.InvalidLifetime);
            token = CreateToken(jwks, TokenValidationStatus.InvalidLifetime, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.MissingAudience);
            token = CreateToken(jwks, TokenValidationStatus.MissingAudience, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.MissingIssuer);
            token = CreateToken(jwks, TokenValidationStatus.MissingIssuer, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.NoExpiration);
            token = CreateToken(jwks, TokenValidationStatus.NoExpiration, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.NotYetValid);
            token = CreateToken(jwks, TokenValidationStatus.NotYetValid, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.Success);
            token = CreateToken(jwks, TokenValidationStatus.InvalidSignature, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.Success);
            token = CreateToken(jwks, TokenValidationStatus.MalformedSignature, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.Success);
            token = CreateToken(jwks, TokenValidationStatus.MalformedToken, payload);
            jwts.Add(token);

            payload = CreatePayload(descriptor, TokenValidationStatus.Success);
            token = CreateToken(jwks, TokenValidationStatus.MissingSignature, payload);
            jwts.Add(token);

            return jwts;
        }

        private static System.IdentityModel.Tokens.Jwt.JwtPayload CreatePayload(JsonWebTokenDescriptor descriptor, TokenValidationStatus status)
        {
            var payload = new System.IdentityModel.Tokens.Jwt.JwtPayload();
            foreach (var claim in descriptor.Payload)
            {
                switch (status)
                {
                    case TokenValidationStatus.NoExpiration:
                        if (claim.Key == "exp")
                        {
                            continue;
                        }
                        break;
                    case TokenValidationStatus.MalformedToken:
                        break;
                    case TokenValidationStatus.InvalidSignature:
                        break;
                    case TokenValidationStatus.KeyNotFound:
                        break;
                    case TokenValidationStatus.MalformedSignature:
                        break;
                    case TokenValidationStatus.MissingSignature:
                        break;
                    case TokenValidationStatus.InvalidAudience:
                        if (claim.Key == "aud")
                        {
                            payload.Add(claim.Key, claim.Value + "XXX");
                            continue;
                        }
                        break;
                    case TokenValidationStatus.MissingAudience:
                        if (claim.Key == "aud")
                        {
                            continue;
                        }
                        break;
                    case TokenValidationStatus.InvalidIssuer:
                        if (claim.Key == "iss")
                        {
                            payload.Add(claim.Key, claim.Value + "XXX");
                            continue;
                        }
                        break;
                    case TokenValidationStatus.MissingIssuer:
                        if (claim.Key == "iss")
                        {
                            continue;
                        }
                        break;
                    case TokenValidationStatus.TokenReplayed:
                        break;
                    case TokenValidationStatus.Expired:
                        if (claim.Key == "exp")
                        {
                            payload.Add(claim.Key, 1500000000);
                            continue;
                        }
                        if (claim.Key == "nbf")
                        {
                            payload.Add(claim.Key, 1400000000);
                            continue;
                        }
                        break;
                    case TokenValidationStatus.InvalidLifetime:
                        if (claim.Key == "exp")
                        {
                            payload.Add(claim.Key, 1799999999);
                            continue;
                        }
                        if (claim.Key == "nbf")
                        {
                            payload.Add(claim.Key, 1800000000);
                            continue;
                        }
                        break;
                    case TokenValidationStatus.NotYetValid:
                        if (claim.Key == "exp")
                        {
                            payload.Add(claim.Key, 2100000000);
                            continue;
                        }
                        if (claim.Key == "nbf")
                        {
                            payload.Add(claim.Key, 2000000000);
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

                payload.Add(claim.Key, claim.Value);
            }

            return payload;
        }

        private static JObject CreateToken(JsonWebKeySet jwks, TokenValidationStatus status, System.IdentityModel.Tokens.Jwt.JwtPayload payload)
        {
            var key = jwks.Keys.First(k => k.Use == "sig" && k.Alg == "HS256");
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(new Microsoft.IdentityModel.Tokens.JsonWebKey(key.ToString()), key.Alg);
            var header = new System.IdentityModel.Tokens.Jwt.JwtHeader(signingCredentials);
            header.Remove("typ");
            switch (status)
            {
                case TokenValidationStatus.KeyNotFound:
                    header["kid"] += "x";
                    break;
                case TokenValidationStatus.MissingEncryptionAlgorithm:
                    break;
                default:
                    break;
            }

            var token = new JwtSecurityToken(header, payload);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(token);

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
            return o;
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