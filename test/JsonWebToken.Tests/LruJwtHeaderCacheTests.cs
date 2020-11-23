using System;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Tests
{
    public class LruJwtHeaderCacheJwsTests
    {
        public class JwsHeader
        {
            [Fact]
            public void AddHeader_WithKid()
            {
                const int Count = 10;

                var cache = new LruJwtHeaderCache();
                byte[] binaryHeader;
                var headers = new JwtHeader[10];
                JwtHeader header;
                for (int i = 0; i < Count; i++)
                {
                    string kid = i.ToString();
                    binaryHeader = new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                    headers[i] = header = new JwtHeader
                {
                    { "alg", "whatever" }
                };
                    cache.AddHeader(header, SignatureAlgorithm.HmacSha256, JsonEncodedText.Encode(kid), default, binaryHeader);
                }

                Assert.Equal(10, cache.Count);

                for (int i = 0; i < Count - 1; i++)
                {
                    Assert.False(cache.TryGetHeader(headers[i], SignatureAlgorithm.None, default, default, out _));
                }

                Assert.True(cache.TryGetHeader(headers[9], SignatureAlgorithm.None, default, default, out binaryHeader));
                Assert.Equal(binaryHeader, new byte[10] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

                for (int i = 0; i < Count; i++)
                {
                    var kid = JsonEncodedText.Encode(i.ToString());
                    Assert.True(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, kid, default, out binaryHeader));
                    Assert.Equal(binaryHeader, new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
                }

                Assert.False(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, JsonEncodedText.Encode("X"), default, out _));
                Assert.False(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha384, JsonEncodedText.Encode("1"), default, out _));
                Assert.False(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, JsonEncodedText.Encode("1"), "typ", out _));

                header = new JwtHeader
            {
                {  "alg", "whatever" },
                {  "kid", "whatever" },
                {  "other", "whatever" }
            };
                Assert.False(cache.TryGetHeader(header, SignatureAlgorithm.HmacSha256, JsonEncodedText.Encode("1"), default, out _));
            }

            [Fact]
            public void AddHeader_BeyondCapacity()
            {
                const int Count = 20;
                Debug.Assert(Count > LruJwtHeaderCache.MaxSize);
                var cache = new LruJwtHeaderCache();
                byte[] binaryHeader;
                JwtHeader header = new JwtHeader
            {
                { "alg", "whatever" }
            };
                for (int i = 0; i < Count; i++)
                {
                    var kid = JsonEncodedText.Encode(i.ToString());
                    binaryHeader = new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                    cache.AddHeader(header, SignatureAlgorithm.HmacSha256, kid, default, binaryHeader);
                }

                Assert.Equal(Count - LruJwtHeaderCache.MaxSize, cache.Count);

                for (int i = 0; i < LruJwtHeaderCache.MaxSize; i++)
                {
                    var kid = JsonEncodedText.Encode(i.ToString());
                    Assert.False(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, kid, default, out _));
                }

                for (int i = LruJwtHeaderCache.MaxSize; i < Count; i++)
                {
                    var kid = JsonEncodedText.Encode(i.ToString());
                    Assert.True(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, kid, default, out binaryHeader));
                    Assert.Equal(binaryHeader, new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
                }
            }

            [Fact]
            public void AddHeader_Parallel()
            {
                var cache = new LruJwtHeaderCache();

                var p = Parallel.For(0, 100, j =>
                {
                    for (int i = 0; i < 1000; i++)
                    {
                        var header = new JwtHeader
                        {
                            { "alg", "whatever" }
                        };
                        cache.AddHeader(header, SignatureAlgorithm.HmacSha256, JsonEncodedText.Encode(i.ToString()), default, ReadOnlySpan<byte>.Empty);
                    }
                });

                Assert.True(cache.Validate());
            }
        }

        public class JweHeader
        {
            [Fact]
            public void AddHeader_WithKid()
            {
                const int Count = 10;

                var cache = new LruJwtHeaderCache();
                byte[] binaryHeader;
                var headers = new JwtHeader[10];
                JwtHeader header;
                for (int i = 0; i < Count; i++)
                {
                    var kid = JsonEncodedText.Encode(i.ToString());
                    binaryHeader = new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                    headers[i] = header = new JwtHeader
                    {
                        { "alg", "whatever" },
                        { "end", "whatever" }
                    };
                    cache.AddHeader(header, KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, kid, default, default, binaryHeader);
                }

                Assert.Equal(10, cache.Count);

                for (int i = 0; i < Count - 1; i++)
                {
                    Assert.False(cache.TryGetHeader(headers[i], KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, default, default, default, out _));
                }

                Assert.True(cache.TryGetHeader(headers[9], KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, default, default, default, out binaryHeader));
                Assert.Equal(binaryHeader, new byte[10] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

                for (int i = 0; i < Count; i++)
                {
                    var kid = JsonEncodedText.Encode(i.ToString());
                    Assert.True(cache.TryGetHeader(new JwtHeader(), KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, kid, default, default, out binaryHeader));
                    Assert.Equal(binaryHeader, new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
                }

                // Assert for parameters not in cache
                Assert.False(cache.TryGetHeader(new JwtHeader(), KeyManagementAlgorithm.Aes192GcmKW, EncryptionAlgorithm.Aes128CbcHmacSha256, JsonEncodedText.Encode("1"), default, default, out _));
                Assert.False(cache.TryGetHeader(new JwtHeader(), KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes256Gcm, JsonEncodedText.Encode("1"), default, default, out _));
                Assert.False(cache.TryGetHeader(new JwtHeader(), KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, JsonEncodedText.Encode("X"), default, default, out _));
                Assert.False(cache.TryGetHeader(new JwtHeader(), KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, JsonEncodedText.Encode("1"), "Y", default, out _));
                Assert.False(cache.TryGetHeader(new JwtHeader(), KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, JsonEncodedText.Encode("1"), default, "Z", out _));

                // Assert for header with too much parameters
                header = new JwtHeader
                {
                    {  "alg", "whatever" },
                    {  "kid", "whatever" },
                    {  "other1", "whatever" },
                    {  "other2", "whatever" },
                    {  "other3", "whatever" }
                };
                Assert.False(cache.TryGetHeader(header, KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, JsonEncodedText.Encode("1"), default, default, out _));
            }

            [Fact]
            public void AddHeader_BeyondCapacity()
            {
                const int Count = 20;
                Debug.Assert(Count > LruJwtHeaderCache.MaxSize);
                var cache = new LruJwtHeaderCache();
                byte[] binaryHeader;
                JwtHeader header = new JwtHeader
            {
                { "alg", "whatever" }
            };
                for (int i = 0; i < Count; i++)
                {
                    var kid = JsonEncodedText.Encode(i.ToString());
                    binaryHeader = new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                    cache.AddHeader(header, KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, kid, default, default, binaryHeader);
                }

                Assert.Equal(Count - LruJwtHeaderCache.MaxSize, cache.Count);

                for (int i = 0; i < LruJwtHeaderCache.MaxSize; i++)
                {
                    var kid = JsonEncodedText.Encode(i.ToString());
                    Assert.False(cache.TryGetHeader(new JwtHeader(), KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, kid, default, default, out _));
                }

                for (int i = LruJwtHeaderCache.MaxSize; i < Count; i++)
                {
                    var kid = JsonEncodedText.Encode(i.ToString());
                    Assert.True(cache.TryGetHeader(new JwtHeader(), KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, kid, default, default, out binaryHeader));
                    Assert.Equal(binaryHeader, new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
                }
            }

            [Fact]
            public void AddHeader_Parallel()
            {
                var cache = new LruJwtHeaderCache();

                var p = Parallel.For(0, 100, j =>
                {
                    for (int i = 0; i < 1000; i++)
                    {
                        var header = new JwtHeader
                        {
                        { "alg", "whatever" }
                        };
                        cache.AddHeader(header, KeyManagementAlgorithm.Aes128KW, EncryptionAlgorithm.Aes128CbcHmacSha256, JsonEncodedText.Encode(i.ToString()), default, default, ReadOnlySpan<byte>.Empty);
                    }
                });

                Assert.True(cache.Validate());
            }
        }
    }
}