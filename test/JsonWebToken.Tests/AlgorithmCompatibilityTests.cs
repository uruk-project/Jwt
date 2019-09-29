using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public abstract class AlgorithmTests<T> where T : class, IAlgorithm
    {
        public abstract bool TryParse(ReadOnlySpan<byte> value, out T algorithm);

        public virtual void TryParse_Success(T expected)
        {
            var parsed = TryParse(expected.Utf8Name, out var algorithm);
            Assert.True(parsed);
            Assert.NotNull(algorithm);
            Assert.Same(expected, algorithm);
        }

        public abstract bool TryParseSlow(ref Utf8JsonReader reader, out T algorithm);

        public virtual void TryParseSlow_Success(T expected)
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes("\"" + expected.Name + "\""));
            reader.Read();
            var parsed = TryParseSlow(ref reader, out var algorithm);
            Assert.True(parsed);
            Assert.NotNull(algorithm);
            Assert.Same(expected, algorithm);
        }
    }

    public class AlgorithmFixture<T> : IEnumerable<object[]>
    {
        public IEnumerator<object[]> GetEnumerator()
        {
            var type = typeof(T);
            var properties = type.GetFields(BindingFlags.Public | BindingFlags.Static).Where(p => p.FieldType == typeof(T));
            foreach (var item in properties)
            {
                yield return new object[] { item.GetValue(null) };
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            throw new NotImplementedException();
        }
    }

    public class SignatureAlgorithmTests : AlgorithmTests<SignatureAlgorithm>
    {
        public override bool TryParse(ReadOnlySpan<byte> value, out SignatureAlgorithm algorithm)
        {
            return SignatureAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out SignatureAlgorithm algorithm)
        {
            return SignatureAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<SignatureAlgorithm>))]
        public override void TryParse_Success(SignatureAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<SignatureAlgorithm>))]
        public override void TryParseSlow_Success(SignatureAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }
    }

    public class KeyManagementAlgorithmTests : AlgorithmTests<KeyManagementAlgorithm>
    {
        public override bool TryParse(ReadOnlySpan<byte> value, out KeyManagementAlgorithm algorithm)
        {
            return KeyManagementAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out KeyManagementAlgorithm algorithm)
        {
            return KeyManagementAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<KeyManagementAlgorithm>))]
        public override void TryParse_Success(KeyManagementAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<KeyManagementAlgorithm>))]
        public override void TryParseSlow_Success(KeyManagementAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }
    }

    public class CompressionAlgorithmTests : AlgorithmTests<CompressionAlgorithm>
    {
        public override bool TryParse(ReadOnlySpan<byte> value, out CompressionAlgorithm algorithm)
        {
            return CompressionAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out CompressionAlgorithm algorithm)
        {
            return CompressionAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<CompressionAlgorithm>))]
        public override void TryParse_Success(CompressionAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<CompressionAlgorithm>))]
        public override void TryParseSlow_Success(CompressionAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }
    }

    public class EncryptionAlgorithmTests : AlgorithmTests<EncryptionAlgorithm>
    {
        public override bool TryParse(ReadOnlySpan<byte> value, out EncryptionAlgorithm algorithm)
        {
            return EncryptionAlgorithm.TryParse(value, out algorithm);
        }

        public override bool TryParseSlow(ref Utf8JsonReader reader, out EncryptionAlgorithm algorithm)
        {
            return EncryptionAlgorithm.TryParseSlow(ref reader, out algorithm);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<EncryptionAlgorithm>))]
        public override void TryParse_Success(EncryptionAlgorithm expected)
        {
            base.TryParse_Success(expected);
        }

        [Theory]
        [ClassData(typeof(AlgorithmFixture<EncryptionAlgorithm>))]
        public override void TryParseSlow_Success(EncryptionAlgorithm expected)
        {
            base.TryParseSlow_Success(expected);
        }
    }

    public class AlgorithmCompatibilityTests : IClassFixture<KeyFixture>
    {
        public AlgorithmCompatibilityTests(KeyFixture keys)
        {
            _keys = keys;
        }

        private static readonly SymmetricJwk _signingKey = SymmetricJwk.GenerateKey(256, SignatureAlgorithm.HmacSha256);
        private readonly KeyFixture _keys;

        [Theory]
        [MemberData(nameof(GetCompatibleAlgorithms))]
        public void Compatible(EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            var writer = new JwtWriter();
            foreach (var encryptionKey in SelectEncryptionKey(enc.Name, alg.Name))
            {
                var descriptor = new JweDescriptor
                {
                    EncryptionKey = encryptionKey,
                    EncryptionAlgorithm = enc,
                    Algorithm = alg,
                    Payload = new JwsDescriptor
                    {
                        SigningKey = _signingKey,
                        Algorithm = SignatureAlgorithm.HmacSha256,
                        Subject = "Alice"
                    }
                };

                var token = writer.WriteToken(descriptor);

                var reader = new JwtReader(_keys.Jwks);

                var policy = new TokenValidationPolicyBuilder()
                    .RequireSignature(_signingKey)
                        .Build();

                var result = reader.TryReadToken(token, policy);
                Assert.Equal(TokenValidationStatus.Success, result.Status);
                Assert.Equal("Alice", result.Token.Subject);
            }
        }

        private IEnumerable<Jwk> SelectEncryptionKey(string enc, string alg)
        {
            switch (alg)
            {
                case "A128KW":
                case "A128GCMKW":
                    yield return _keys.Symmetric128Key;
                    break;
                case "A192KW":
                case "A192GCMKW":
                    yield return _keys.Symmetric192Key;
                    break;
                case "A256KW":
                case "A256GCMKW":
                    yield return _keys.Symmetric256Key;
                    break;
                case "dir":
                    switch (enc)
                    {
                        case "A128CBC-HS256":
                            yield return _keys.Symmetric256Key;
                            break;
                        case "A128GCM":
                            yield return _keys.Symmetric128Key;
                            break;
                        case "A192CBC-HS384":
                            yield return _keys.Symmetric384Key;
                            break;
                        case "A192GCM":
                            yield return _keys.Symmetric192Key;
                            break;
                        case "A256CBC-HS512":
                            yield return _keys.Symmetric512Key;
                            break;
                        case "A256GCM":
                            yield return _keys.Symmetric256Key;
                            break;
                        default:
                            throw new NotSupportedException();
                    }
                    break;
                case "RSA-OAEP":
                case "RSA-OAEP-256":
                case "RSA-OAEP-384":
                case "RSA-OAEP-512":
                case "RSA1_5":
                    yield return _keys.PrivateRsa2048Key;
                    break;
#if !NET461
                case "ECDH-ES+A128KW":
                case "ECDH-ES+A192KW":
                case "ECDH-ES+A256KW":
                    yield return _keys.PrivateEcc256Key;
                    yield return _keys.PrivateEcc384Key;
                    yield return _keys.PrivateEcc512Key;
                    break;
                case "ECDH-ES":
                    yield return _keys.PrivateEcc256Key;
                    yield return _keys.PrivateEcc384Key;
                    yield return _keys.PrivateEcc512Key;
                    break;
#endif
                default:
                    throw new NotSupportedException();
            }

            yield break;
        }

        public static IEnumerable<object[]> GetCompatibleAlgorithms()
        {
            foreach (var enc in GetEncryptionAlgorithms())
            {
                foreach (var alg in GetKeyManagementAlgorithms())
                {
                    yield return new object[] { enc, alg };
                }
            }
        }

        public static IEnumerable<KeyManagementAlgorithm> GetKeyManagementAlgorithms()
        {
            yield return KeyManagementAlgorithm.Aes128KW;
            yield return KeyManagementAlgorithm.Aes192KW;
            yield return KeyManagementAlgorithm.Aes256KW;
            yield return KeyManagementAlgorithm.Direct;

#if NETCOREAPP3_0
            yield return KeyManagementAlgorithm.Aes128GcmKW;
            yield return KeyManagementAlgorithm.Aes192GcmKW;
            yield return KeyManagementAlgorithm.Aes256GcmKW;
#endif
            yield return KeyManagementAlgorithm.RsaOaep;
            yield return KeyManagementAlgorithm.RsaPkcs1;
#if !NETFRAMEWORK
            yield return KeyManagementAlgorithm.RsaOaep256;
            yield return KeyManagementAlgorithm.RsaOaep384;
            yield return KeyManagementAlgorithm.RsaOaep512;
#endif
#if NETCOREAPP
            yield return KeyManagementAlgorithm.EcdhEs;
            yield return KeyManagementAlgorithm.EcdhEsAes128KW;
            yield return KeyManagementAlgorithm.EcdhEsAes192KW;
            yield return KeyManagementAlgorithm.EcdhEsAes256KW;
#endif
        }

        private static IEnumerable<EncryptionAlgorithm> GetEncryptionAlgorithms()
        {
            yield return EncryptionAlgorithm.Aes128CbcHmacSha256;
            yield return EncryptionAlgorithm.Aes192CbcHmacSha384;
            yield return EncryptionAlgorithm.Aes256CbcHmacSha512;
#if NETCOREAPP3_0
            yield return EncryptionAlgorithm.Aes128Gcm;
            yield return EncryptionAlgorithm.Aes192Gcm;
            yield return EncryptionAlgorithm.Aes256Gcm;
#endif
        }
    }
}