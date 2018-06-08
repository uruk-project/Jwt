using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JsonWebToken.Performance
{
    public static class Tokens
    {
        public static IDictionary<string, string> ValidTokens { get; }

        public static SymmetricJwk SigningKey { get; }

        public static SymmetricJwk EncryptionKey { get; }

        public static IDictionary<string, JObject> Payloads { get; }

        static Tokens()
        {
            var signingKey = CreateSigningKey();
            var encryptionKey = CreateEncryptionKey();
            var payloads = CreatePayloads();
            ValidTokens = CreateTokens(payloads, signingKey, encryptionKey);
            Payloads = payloads;
            SigningKey = signingKey;
            EncryptionKey = encryptionKey;
        }

        private static SymmetricJwk CreateSigningKey()
        {
            return SymmetricJwk.GenerateKey(128, SignatureAlgorithms.HmacSha256);
        }

        private static SymmetricJwk CreateEncryptionKey()
        {
            return SymmetricJwk.GenerateKey(128, KeyManagementAlgorithms.Aes128KW);
        }

        private static IDictionary<string, JObject> CreatePayloads()
        {
            byte[] bigData = new byte[1024 * 64];
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
                        { "exp", 1628184845}
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
                        { "big_claim", Convert.ToBase64String(bigData) }
                    }
                },
            };

            return payloads;
        }

        private static IDictionary<string, string> CreateTokens(IDictionary<string, JObject> payloads, SymmetricJwk signingKey, SymmetricJwk encryptionKey)
        {
            var writer = new JsonWebTokenWriter();
            var descriptors = new Dictionary<string, string>();
            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    Key = signingKey
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
                //Console.WriteLine(descriptor);
                //Console.WriteLine(writer.WriteToken(descriptor));

                descriptors.Add(payload.Key, writer.WriteToken(descriptor));
            }

            foreach (var payload in payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    Key = signingKey
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
                    Key = encryptionKey,
                    EncryptionAlgorithm = ContentEncryptionAlgorithms.Aes128CbcHmacSha256,
                    ContentType = "JWT"
                };

                descriptors.Add("enc-" + payload.Key, writer.WriteToken(jwe));
            }

            return descriptors;
        }
    }
}
