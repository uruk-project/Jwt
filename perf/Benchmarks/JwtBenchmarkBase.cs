using BenchmarkDotNet.Attributes;
using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken.Performance
{
    [Config(typeof(AllTfmCoreConfig))]
    public abstract class JwtBenchmarkBase
    {
        public JwtBenchmarkBase()
        {
            // Workaround for https://github.com/dotnet/BenchmarkDotNet/issues/837
            WriteJwtCore("JWT-empty");
            ValidateJwtCore("JWT-empty", TokenValidationPolicy.NoValidation);
        }

        private static readonly SymmetricJwk SigningKey = Tokens.SigningKey;

        private static readonly SymmetricJwk EncryptionKey = Tokens.EncryptionKey;

        private static readonly Microsoft.IdentityModel.Tokens.JsonWebKey WilsonSharedKey = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(SigningKey.ToString());

        public static readonly JwtWriter Writer = new JwtWriter();
        public static readonly JwtReader Reader = new JwtReader(Tokens.EncryptionKey);
        protected static readonly TokenValidationPolicy policyWithSignatureValidation = new TokenValidationPolicyBuilder().RequireSignature(Tokens.SigningKey).Build();

        private static readonly Dictionary<string, JwtDescriptor> JwtPayloads = CreateJwtDescriptors();
        private static readonly Dictionary<string, byte[]> JwtTokens = CreateJwtTokens();

        public abstract void WriteJwt(string token);

        public abstract void ValidateJwt(string token);

        protected void WriteJwtCore(string token)
        {
            var value = Writer.WriteToken(JwtPayloads[token]);
        }

        protected void ValidateJwtCore(string token, TokenValidationPolicy policy)
        {
            var result = Reader.TryReadToken(JwtTokens[token], policy);
            EnsureResult(result);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void EnsureResult(TokenValidationResult result)
        {
            if (!result.Succedeed)
            {
                throw new Exception(result.Status.ToString());
            }
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
                            descriptor.AddClaim(property.Name, EpochTime.ToDateTime((long)property.Value));
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
                foreach (var compression in new[] { null, CompressionAlgorithm.Deflate })
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
                        EncryptionAlgorithm = EncryptionAlgorithm.Aes128CbcHmacSha256,
                        CompressionAlgorithm = compression
                    };

                    var descriptorName = "JWE-";
                    if (compression != null)
                    {
                        descriptorName += compression + "-";
                    }

                    descriptorName += payload.Key;
                    descriptors.Add(descriptorName, jwe);
                }
            }

            return descriptors;
        }

        private static Dictionary<string, byte[]> CreateJwtTokens()
        {
            var tokens = new Dictionary<string, byte[]>();
            foreach (var item in JwtPayloads)
            {
                tokens.Add(item.Key, Encoding.UTF8.GetBytes(Writer.WriteToken(item.Value)));
            }

            return tokens;
        }
    }
}