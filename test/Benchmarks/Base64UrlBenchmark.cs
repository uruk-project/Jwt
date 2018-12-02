using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using JsonWebToken.Internal;
using System;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{

    [Config(typeof(HardwareIntrinsicsCustomConfig))]
    public class Base64UrlWriteBenchmark : Base64UrlBenchmark
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public void WriteJwt_Classic(string token)
        {
            Base64Url.EnableSimd = false;
            var value = Writer.WriteToken(JwtPayloads[token]);
        }

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetTokens))]
        public void WriteJwt_Simd(string token)
        {
            Base64Url.EnableSimd = true;
            var value = Writer.WriteToken(JwtPayloads[token]);
        }
    }

    [Config(typeof(HardwareIntrinsicsCustomConfig))]
    public class Base64UrlReadBenchmark : Base64UrlBenchmark
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokens))]
        public void ReadJwt_Classic(string token)
        {
            Base64Url.EnableSimd = false;
            var value = Reader.TryReadToken(Tokens.ValidTokens[token], TokenValidationPolicy.NoValidation);
            if (!value.Succedeed)
            {
                throw new Exception(value.Status.ToString(), value.Exception);
            }
        }

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetTokens))]
        public void ReadJwt_Simd(string token)
        {
            Base64Url.EnableSimd = true;
            var value = Reader.TryReadToken(Tokens.ValidTokens[token], TokenValidationPolicy.NoValidation);
            if (!value.Succedeed)
            {
                throw new Exception(value.Status.ToString(), value.Exception);
            }
        }
    }

    [MemoryDiagnoser]
    public class Base64UrlBenchmark
    {
        private static readonly SymmetricJwk SigningKey = Tokens.SigningKey;

        private static readonly SymmetricJwk EncryptionKey = Tokens.EncryptionKey;

        public static readonly JwtWriter Writer = new JwtWriter();
        public static readonly JwtReader Reader = new JwtReader(Tokens.EncryptionKey);
        private static readonly TokenValidationPolicy policy = TokenValidationPolicy.NoValidation;

        protected static readonly Dictionary<string, JwtDescriptor> JwtPayloads = CreateJwtDescriptors();

        public IEnumerable<string> GetTokens()
        {
            yield return "JWS-empty";
            yield return "JWS-small";
            yield return "JWS-medium";
            yield return "JWS-big";
            //yield return new[] { "JWE-empty" };
            //yield return new[] { "JWE-small" };
            //yield return new[] { "JWE-medium" };
            //yield return new[] { "JWE-big" };
            //yield return new[] { "JWE-DEF-empty" };
            //yield return new[] { "JWE-DEF-small" };
            //yield return new[] { "JWE-DEF-medium" };
            //yield return new[] { "JWE-DEF-big" };
        }

        private static Dictionary<string, JwtDescriptor> CreateJwtDescriptors()
        {
            var descriptors = new Dictionary<string, JwtDescriptor>();
            foreach (var payload in Tokens.Payloads)
            {
                var descriptor = new JwsDescriptor()
                {
                    Algorithm = SignatureAlgorithm.None
                    //Key = SigningKey
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
    }
}
