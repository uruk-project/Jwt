using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Tests
{
    public class LruJwtHeaderCacheTests
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
                cache.AddHeader(header, SignatureAlgorithm.HmacSha256, kid, null, binaryHeader);
            }

            Assert.Equal(10, cache.Count);

            for (int i = 0; i < Count - 1; i++)
            {
                Assert.False(cache.TryGetHeader(headers[i], SignatureAlgorithm.None, null, null, out _));
            }

            Assert.True(cache.TryGetHeader(headers[9], SignatureAlgorithm.None, null, null, out binaryHeader));
            Assert.Equal(binaryHeader, new byte[10] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

            for (int i = 0; i < Count; i++)
            {
                string kid = i.ToString();
                Assert.True(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, kid, null, out binaryHeader));
                Assert.Equal(binaryHeader, new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
            }

            Assert.False(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, "X", null, out _));
            Assert.False(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha384, "1", null, out _));
            Assert.False(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, "1", "typ", out _));

            header = new JwtHeader
            {
                {  "alg", "whatever" },
                {  "kid", "whatever" },
                {  "other", "whatever" }
            };
            Assert.False(cache.TryGetHeader(header, SignatureAlgorithm.HmacSha256, "1", null, out _));
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
                string kid = i.ToString();
                binaryHeader = new byte[10] { (byte)i, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                cache.AddHeader(header, SignatureAlgorithm.HmacSha256, kid, null, binaryHeader);
            }

            Assert.Equal(Count - LruJwtHeaderCache.MaxSize, cache.Count);

            for (int i = 0; i < LruJwtHeaderCache.MaxSize; i++)
            {
                string kid = i.ToString();
                Assert.False(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, kid, null, out _));
            }

            for (int i = LruJwtHeaderCache.MaxSize; i < Count; i++)
            {
                string kid = i.ToString();
                Assert.True(cache.TryGetHeader(new JwtHeader(), SignatureAlgorithm.HmacSha256, kid, null, out binaryHeader));
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
                    cache.AddHeader(header, SignatureAlgorithm.HmacSha256, i.ToString(), null, ReadOnlySpan<byte>.Empty);
                }
            });

            Assert.True(cache.Validate());
        }
    }
}