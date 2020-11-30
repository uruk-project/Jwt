using System;
using System.Collections.Generic;
using System.Linq;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Order;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    [MarkdownExporterAttribute.GitHub]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    public class SignatureBenchmark
    {
        [ParamsSource(nameof(GetDescriptor))]
        public JwsDescriptorWrapper Descriptor { get; set; }

        private static readonly JwtWriter _writer = new JwtWriter();

        [Benchmark(Baseline = true)]
        public byte[] Sign()
        {
            return _writer.WriteToken(Descriptor.Descriptor);
        }

        public static IEnumerable<JwsDescriptorWrapper> GetDescriptor()
        {
            yield return CreateDescriptor(SignatureAlgorithm.HS256);
            yield return CreateDescriptor(SignatureAlgorithm.HS384);
            yield return CreateDescriptor(SignatureAlgorithm.HS512);
            yield return CreateDescriptor(SignatureAlgorithm.RS256);
            yield return CreateDescriptor(SignatureAlgorithm.RS384);
            yield return CreateDescriptor(SignatureAlgorithm.RS512);
            yield return CreateDescriptor(SignatureAlgorithm.PS256);
            yield return CreateDescriptor(SignatureAlgorithm.PS384);
            yield return CreateDescriptor(SignatureAlgorithm.PS512);
            yield return CreateDescriptor(SignatureAlgorithm.ES256X);
            yield return CreateDescriptor(SignatureAlgorithm.ES256);
            yield return CreateDescriptor(SignatureAlgorithm.ES384);
            yield return CreateDescriptor(SignatureAlgorithm.ES512);
            yield return CreateDescriptor(SignatureAlgorithm.None);
        }

        public class JwsDescriptorWrapper
        {
            private readonly JwsDescriptor _descriptor;
            public JwsDescriptor Descriptor => _descriptor;
            public JwsDescriptorWrapper(JwsDescriptor descriptor)
            {
                _descriptor = descriptor;
            }

            public override string ToString()
            {
                return _descriptor.Alg.ToString();
            }
        }

        private static JwsDescriptorWrapper CreateDescriptor(SignatureAlgorithm algorithm)
        {
            var jwk = algorithm.Category switch
            {
                Cryptography.AlgorithmCategory.None => Jwk.None,
                Cryptography.AlgorithmCategory.EllipticCurve => ECJwk.GeneratePrivateKey(algorithm),
                Cryptography.AlgorithmCategory.Rsa => RsaJwk.GeneratePrivateKey(4096, algorithm),
                Cryptography.AlgorithmCategory.Aes => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.AesGcm => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.Hmac => SymmetricJwk.GenerateKey(algorithm),
                _ => throw new InvalidOperationException()
            };

            var descriptor = new JwsDescriptor(jwk, algorithm)
            {
                Payload = new JwtPayload
                {
                    { JwtClaimNames.Iat, EpochTime.UtcNow },
                    { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                    { JwtClaimNames.Iss, "https://idp.example.com/" },
                    { JwtClaimNames.Aud, "636C69656E745F6964" }
                }
            };
            return new JwsDescriptorWrapper(descriptor);
        }
    }

    [MemoryDiagnoser]
    [MarkdownExporterAttribute.GitHub]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    public class SignatureValidationBenchmark
    {
        [ParamsSource(nameof(GetDescriptor))]
        public JwsWrapper Token { get; set; }

        [Benchmark(Baseline = true)]
        public bool Parse()
        {
            var result = Jwt.TryParse(Token.Data, Token.Policy, out var jwt);
            jwt.Dispose();
            return result;
        }

        public static IEnumerable<JwsWrapper> GetDescriptor()
        {
            yield return CreateDescriptor(SignatureAlgorithm.HS256);
            yield return CreateDescriptor(SignatureAlgorithm.HS384);
            yield return CreateDescriptor(SignatureAlgorithm.HS512);
            yield return CreateDescriptor(SignatureAlgorithm.RS256);
            yield return CreateDescriptor(SignatureAlgorithm.RS384);
            yield return CreateDescriptor(SignatureAlgorithm.RS512);
            yield return CreateDescriptor(SignatureAlgorithm.PS256);
            yield return CreateDescriptor(SignatureAlgorithm.PS384);
            yield return CreateDescriptor(SignatureAlgorithm.PS512);
            yield return CreateDescriptor(SignatureAlgorithm.ES256X);
            yield return CreateDescriptor(SignatureAlgorithm.ES256);
            yield return CreateDescriptor(SignatureAlgorithm.ES384);
            yield return CreateDescriptor(SignatureAlgorithm.ES512);
        }

        public class JwsWrapper
        {
            private readonly byte[] _token;
            private readonly SignatureAlgorithm _algorithm;

            public byte[] Data => _token;

            public TokenValidationPolicy Policy { get; }

            public JwsWrapper(byte[] token, SignatureAlgorithm algorithm, TokenValidationPolicy policy)
            {
                _token = token;
                _algorithm = algorithm;
                Policy = policy;
            }

            public override string ToString()
            {
                return _algorithm.ToString();
            }
        }

        private static JwsWrapper CreateDescriptor(SignatureAlgorithm algorithm)
        {
            var jwk = algorithm.Category switch
            {
                Cryptography.AlgorithmCategory.None => Jwk.None,
                Cryptography.AlgorithmCategory.EllipticCurve => ECJwk.GeneratePrivateKey(algorithm),
                Cryptography.AlgorithmCategory.Rsa => RsaJwk.GeneratePrivateKey(4096, algorithm),
                Cryptography.AlgorithmCategory.Aes => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.AesGcm => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.Hmac => SymmetricJwk.GenerateKey(algorithm),
                _ => throw new InvalidOperationException()
            };

            var descriptor = new JwsDescriptor(jwk, algorithm)
            {
                Payload = new JwtPayload
                    {
                        { JwtClaimNames.Iat, EpochTime.UtcNow },
                        { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                        { JwtClaimNames.Iss, "https://idp.example.com/" },
                        { JwtClaimNames.Aud, "636C69656E745F6964" }
                    }
            };
            var policy = new TokenValidationPolicyBuilder()
                .RequireIssuer("https://idp.example.com/", jwk, algorithm)
                .Build();


            var writer = new JwtWriter();
            return new JwsWrapper(writer.WriteToken(descriptor), algorithm, policy);
        }
    }

    [MemoryDiagnoser]
    [MediumRunJob]
    [MarkdownExporterAttribute.GitHub]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    public class DecryptionBenchmark
    {
        public DecryptionBenchmark()
        {
            if (Wrappers is null)
            {
                Wrappers = CreateDescriptors();
            }
        }

        public static Dictionary<string, Dictionary<string, JweWrapper>> Wrappers { get; set; } = CreateDescriptors();

        [ParamsSource(nameof(GetAlg))]
        public string Alg { get; set; }

        [ParamsSource(nameof(GetEnc))]
        public string Enc { get; set; }

        [Benchmark]
        public bool Parse()
        {
            var wrapper = Wrappers[Alg][Enc];

            var result = Jwt.TryParse(wrapper.Data, wrapper.Policy, out var jwt);
            jwt.Dispose();
            return result;
        }

        public static IEnumerable<string> GetAlg()
        {
            return KeyManagementAlgorithm._algorithms.Select(a => a.ToString());
        }

        public static IEnumerable<string> GetEnc()
        {
            return EncryptionAlgorithm._algorithms.Select(a => a.ToString());
        }

        public static Dictionary<string, Dictionary<string, JweWrapper>> CreateDescriptors()
        {
            return GenerateDescriptors()
                .GroupBy(d => d.KeyManagementAlgorithm.ToString())
                .ToDictionary(d => d.Key, d => d.ToDictionary(d2 => d2.EncryptionAlgorithm.ToString(), d2 => d2));
        }

        public static IEnumerable<JweWrapper> GenerateDescriptors()
        {
            foreach (var alg in KeyManagementAlgorithm._algorithms)
            {
                foreach (var enc in EncryptionAlgorithm._algorithms)
                {
                    yield return CreateDescriptor(alg, enc);
                }
            }
        }

        public class JweWrapper
        {
            private readonly byte[] _token;
            private readonly KeyManagementAlgorithm _keyManagementAlgorithm;
            private readonly EncryptionAlgorithm _encryptionAlgorithm;

            public byte[] Data => _token;

            public TokenValidationPolicy Policy { get; }

            public KeyManagementAlgorithm KeyManagementAlgorithm => _keyManagementAlgorithm;

            public EncryptionAlgorithm EncryptionAlgorithm => _encryptionAlgorithm;

            public JweWrapper(byte[] token, KeyManagementAlgorithm keyManagementAlgorithm, EncryptionAlgorithm encryptionAlgorithm, TokenValidationPolicy policy)
            {
                _token = token;
                _keyManagementAlgorithm = keyManagementAlgorithm;
                _encryptionAlgorithm = encryptionAlgorithm;
                Policy = policy;
            }

            public override string ToString()
            {
                return KeyManagementAlgorithm.ToString() + "/" + EncryptionAlgorithm.ToString();
            }
        }

        private static JweWrapper CreateDescriptor(KeyManagementAlgorithm algorithm, EncryptionAlgorithm encryptionAlgorithm)
        {
            var jwk = algorithm.Category switch
            {
                Cryptography.AlgorithmCategory.None => Jwk.None,
                Cryptography.AlgorithmCategory.EllipticCurve => ECJwk.GeneratePrivateKey(EllipticalCurve.P256, algorithm),
                Cryptography.AlgorithmCategory.Rsa => RsaJwk.GeneratePrivateKey(4096, algorithm),
                Cryptography.AlgorithmCategory.Aes => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.AesGcm => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.Hmac => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.Direct => SymmetricJwk.GenerateKey(encryptionAlgorithm),
                Cryptography.AlgorithmCategory.Direct | Cryptography.AlgorithmCategory.EllipticCurve => ECJwk.GeneratePrivateKey(EllipticalCurve.P256),
                _ => throw new InvalidOperationException(algorithm.Category.ToString())
            };

            var descriptor = new JweDescriptor(jwk, algorithm, encryptionAlgorithm)
            {
                Payload = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None)
                {
                    Payload = new JwtPayload
                    {
                        { JwtClaimNames.Iat, EpochTime.UtcNow },
                        { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                        { JwtClaimNames.Iss, "https://idp.example.com/" },
                        { JwtClaimNames.Aud, "636C69656E745F6964" }
                    }
                }
            };
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken("https://idp.example.com/")
                .WithDecryptionKey(jwk)
                .Build();

            var writer = new JwtWriter();
            return new JweWrapper(writer.WriteToken(descriptor), algorithm, encryptionAlgorithm, policy);
        }
    }

    public static class Descriptors
    {
        static Descriptors()
        {
            JweWrappers = CreateDescriptors();
        }

        public static Dictionary<string, Dictionary<string, JweDescriptorWrapper>> JweWrappers { get; set; }

        public static Dictionary<string, Dictionary<string, JweDescriptorWrapper>> CreateDescriptors()
        {
            return GetDescriptor()
                .GroupBy(d => d.Descriptor.Alg.ToString())
                .ToDictionary(d => d.Key, d => d.ToDictionary(d2 => d2.Descriptor.Enc.ToString(), d2 => d2));
        }

        private static JweDescriptorWrapper CreateDescriptor(KeyManagementAlgorithm algorithm, EncryptionAlgorithm encryptionAlgorithm)
        {
            var jwk = algorithm.Category switch
            {
                Cryptography.AlgorithmCategory.None => Jwk.None,
                Cryptography.AlgorithmCategory.EllipticCurve => ECJwk.GeneratePrivateKey(EllipticalCurve.P256, algorithm),
                Cryptography.AlgorithmCategory.Rsa => RsaJwk.GeneratePrivateKey(4096, algorithm),
                Cryptography.AlgorithmCategory.Aes => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.AesGcm => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.Hmac => SymmetricJwk.GenerateKey(algorithm),
                Cryptography.AlgorithmCategory.Direct => SymmetricJwk.GenerateKey(encryptionAlgorithm),
                Cryptography.AlgorithmCategory.Direct | Cryptography.AlgorithmCategory.EllipticCurve => ECJwk.GeneratePrivateKey(EllipticalCurve.P256),
                _ => throw new InvalidOperationException(algorithm.Category.ToString())
            };

            var descriptor = new JweDescriptor(jwk, algorithm, encryptionAlgorithm)
            {
                Payload = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None)
                {
                    Payload = new JwtPayload
                    {
                        { JwtClaimNames.Iat, EpochTime.UtcNow },
                        { JwtClaimNames.Exp, EpochTime.UtcNow + EpochTime.OneHour },
                        { JwtClaimNames.Iss, "https://idp.example.com/" },
                        { JwtClaimNames.Aud, "636C69656E745F6964" }
                    }
                }
            };
            return new JweDescriptorWrapper(descriptor);
        }

        public static IEnumerable<JweDescriptorWrapper> GetDescriptor()
        {
            foreach (var alg in KeyManagementAlgorithm._algorithms)
            {
                foreach (var enc in EncryptionAlgorithm._algorithms)
                {
                    yield return CreateDescriptor(alg, enc);
                }
            }
        }

    }

    public class JweDescriptorWrapper
    {
        private readonly JweDescriptor _descriptor;

        public JweDescriptor Descriptor => _descriptor;

        public JweDescriptorWrapper(JweDescriptor descriptor)
        {
            _descriptor = descriptor;
        }

        public override string ToString()
        {
            return _descriptor.Alg.ToString() + "/" + _descriptor.Enc.ToString();
        }
    }

    [MemoryDiagnoser]
    [MediumRunJob]
    [MarkdownExporterAttribute.GitHub]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    public class EncryptionBenchmark
    {
        [ParamsSource(nameof(GetAlg))]
        public string Alg { get; set; }

        [ParamsSource(nameof(GetEnc))]
        public string Enc { get; set; }

        private static readonly JwtWriter _writer = new JwtWriter();

        [Benchmark]
        public byte[] Encrypt()
        {
            var wrapper = Descriptors.JweWrappers[Alg][Enc];
            return _writer.WriteToken(wrapper.Descriptor);
        }


        public static IEnumerable<string> GetAlg()
        {
            return KeyManagementAlgorithm._algorithms.Select(a => a.ToString());
        }

        public static IEnumerable<string> GetEnc()
        {
            return EncryptionAlgorithm._algorithms.Select(a => a.ToString());
        }
  
    }
}
