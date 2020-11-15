using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class JwsHeaderSerializationCacheBenchmarks
    {
        private static readonly Jwk _signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256);
        private static readonly DisabledJwtHeaderCache _disabledCache = new DisabledJwtHeaderCache();
        private static readonly LruJwtHeaderCache _enabledCache = new LruJwtHeaderCache();
        private static readonly FixedSizedBufferWriter _output = new FixedSizedBufferWriter(8192);

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("2 parameters")]
        public void WithoutCache_2parameters()
        {
            _output.Clear();
            JwsDescriptor descriptor = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256);
            descriptor.Encode(new EncodingContext(_output, _disabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("2 parameters")]
        public void WithCache_2parameters()
        {
            _output.Clear();
            _enabledCache.Clear();
            JwsDescriptor descriptor = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256);
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }
        [Benchmark]
        [BenchmarkCategory("2 parameters")]
        public void WithCacheHit_2parameters()
        {
            _output.Clear();
            JwsDescriptor descriptor = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256);
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("4 parameters")]
        public void WithoutCache_4parameters()
        {
            _output.Clear();
            JwsDescriptor descriptor = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256, "typ", "cty");
            descriptor.Encode(new EncodingContext(_output, _disabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("4 parameters")]
        public void WithCache_4parameters()
        {
            _output.Clear();
            _enabledCache.Clear();
            JwsDescriptor descriptor = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256, "typ", "cty");
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("4 parameters")]
        public void WithCacheHit_4parameters()
        {
            _output.Clear();
            JwsDescriptor descriptor = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256, "typ", "cty");
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("8 parameters")]
        public void WithoutCache_8parameters()
        {
            _output.Clear();
            JwsDescriptor descriptor = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256, "typ", "cty")
            {
                Payload = new JwtPayload
                {
                    { "header5", "value 5" },
                    { "header6", "value 6" },
                    { "header7", "value 7" },
                    { "header8", "value 8" }
                }
            };
            descriptor.Encode(new EncodingContext(_output, _disabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("8 parameters")]
        public void WithCache_8parameters()
        {
            _output.Clear();
            _enabledCache.Clear();
            JwsDescriptor descriptor = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256, "typ", "cty")
            {
                Payload = new JwtPayload
                {
                    { "header5", "value 5" },
                    { "header6", "value 6" },
                    { "header7", "value 7" },
                    { "header8", "value 8" }
                }
            };
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("8 parameters")]
        public void WithCacheHit_8parameters()
        {
            _output.Clear();
            JwsDescriptor descriptor = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256, "typ", "cty")
            {
                Payload = new JwtPayload
                {
                    { "header5", "value 5" },
                    { "header6", "value 6" },
                    { "header7", "value 7" },
                    { "header8", "value 8" }
                }
            };
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }
    }
    [MemoryDiagnoser]
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class JweHeaderSerializationCacheBenchmarks
    {
        private static readonly Jwk _signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256);
        private static readonly Jwk _encryptionKey = SymmetricJwk.GenerateKey(EncryptionAlgorithm.Aes128Gcm);
        private static readonly DisabledJwtHeaderCache _disabledCache = new DisabledJwtHeaderCache();
        private static readonly LruJwtHeaderCache _enabledCache = new LruJwtHeaderCache();
        private static readonly FixedSizedBufferWriter _output = new FixedSizedBufferWriter(8192);

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("4 parameters")]
        public void WithoutCache_4parameters()
        {
            _output.Clear();
            JweDescriptor descriptor = new JweDescriptor(_encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128Gcm)
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256)
            };

            descriptor.Encode(new EncodingContext(_output, _disabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("4 parameters")]
        public void WithCache_4parameters()
        {
            _output.Clear();
            _enabledCache.Clear();
            JweDescriptor descriptor = new JweDescriptor(_encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128Gcm)
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256)
            };
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }
        [Benchmark]
        [BenchmarkCategory("4 parameters")]
        public void WithCacheHit_4parameters()
        {
            _output.Clear();
            JweDescriptor descriptor = new JweDescriptor(_encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128Gcm)
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256)
            };
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("5 parameters")]
        public void WithoutCache_5parameters()
        {
            _output.Clear();
            JweDescriptor descriptor = new JweDescriptor(_encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128Gcm, typ: "typ", cty: "cty")
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256)
            };
            descriptor.Encode(new EncodingContext(_output, _disabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("5 parameters")]
        public void WithCache_5parameters()
        {
            _output.Clear();
            _enabledCache.Clear();
            JweDescriptor descriptor = new JweDescriptor(_encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128Gcm, typ: "typ", cty: "cty")
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256)
            };
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("5 parameters")]
        public void WithCacheHit_5parameters()
        {
            _output.Clear();
            JweDescriptor descriptor = new JweDescriptor(_encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128Gcm, typ: "typ", cty: "cty")
            {
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256)
            };
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }

        [Benchmark(Baseline = true)]
        [BenchmarkCategory("9 parameters")]
        public void WithoutCache_9parameters()
        {
            _output.Clear();
            JweDescriptor descriptor = new JweDescriptor(_encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128Gcm, typ: "typ", cty: "cty")
            {
                Header = new JwtHeader
                {
                    { "header5", "value 5" },
                    { "header6", "value 6" },
                    { "header7", "value 7" },
                    { "header8", "value 8" }
                },
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256)
                {
                }
            };
            descriptor.Encode(new EncodingContext(_output, _disabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("9 parameters")]
        public void WithCache_9parameters()
        {
            _output.Clear();
            _enabledCache.Clear();
            JweDescriptor descriptor = new JweDescriptor(_encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128Gcm, typ: "typ", cty: "cty")
            {
                Header = new JwtHeader
                {
                    { "header5", "value 5" },
                    { "header6", "value 6" },
                    { "header7", "value 7" },
                    { "header8", "value 8" }
                },
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256)
                {
                }
            };
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }

        [Benchmark]
        [BenchmarkCategory("9 parameters")]
        public void WithCacheHit_9parameters()
        {
            _output.Clear();
            JweDescriptor descriptor = new JweDescriptor(_encryptionKey, KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128Gcm, typ: "typ", cty: "cty")
            {
                Header = new JwtHeader
                    {
                        { "header5", "value 5" },
                        { "header6", "value 6" },
                        { "header7", "value 7" },
                        { "header8", "value 8" }
                    },
                Payload = new JwsDescriptor(_signingKey, SignatureAlgorithm.HmacSha256)
                {
                }
            };
            descriptor.Encode(new EncodingContext(_output, _enabledCache, 0, false));
        }
    }
}
