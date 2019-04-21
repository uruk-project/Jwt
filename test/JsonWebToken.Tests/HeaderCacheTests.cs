#if NETCOREAPP3_0
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Tests
{
    public class HeaderCacheTests
    {
        [Fact]
        public void AddHeader()
        {
            const int Count = 10;
            var cache = new JwtHeaderCache();
            var rawHeaders = new byte[10][];
            for (int i = 0; i < Count; i++)
            {
                rawHeaders[i] = new byte[32];
                RandomNumberGenerator.Fill(rawHeaders[i]);
                JwtHeader header = JwtHeader.FromJson($"{{\"kid\":\"{i}\"}}");
                cache.AddHeader(rawHeaders[i], header);
            }

            Assert.Equal("9", cache.Head.Kid);
            Assert.Equal("0", cache.Tail.Kid);

            for (int i = 0; i < Count; i++)
            {
                Assert.True(cache.TryGetHeader(rawHeaders[i], out var header));
            }
        }

        [Fact]
        public void AddHeader_BeyondCapacity()
        {
            const int Count = 20;
            var cache = new JwtHeaderCache();
            var rawHeaders = new byte[Count][];
            for (int i = 0; i < Count; i++)
            {
                rawHeaders[i] = new byte[32];
                RandomNumberGenerator.Fill(rawHeaders[i]);
                JwtHeader header = JwtHeader.FromJson($"{{\"kid\":\"{i}\"}}");
                cache.AddHeader(rawHeaders[i], header);
                Assert.Equal(header, cache.Head);
            }

            Assert.Equal("19", cache.Head.Kid);
            Assert.Equal("10", cache.Tail.Kid);
            for (int i = 0; i < 10; i++)
            {
                Assert.False(cache.TryGetHeader(rawHeaders[i], out var header));
            }

            for (int i = 10; i < Count; i++)
            {
                Assert.True(cache.TryGetHeader(rawHeaders[i], out var header));
            }
        }

        [Fact]
        public void AddHeader_Lru()
        {
            var cache = new JwtHeaderCache();
            var rawHeaders = new byte[10][];
            for (int i = 0; i < 10; i++)
            {
                rawHeaders[i] = new byte[32];
                RandomNumberGenerator.Fill(rawHeaders[i]);
                JwtHeader header = JwtHeader.FromJson($"{{\"kid\":\"{i}\"}}");
                cache.AddHeader(rawHeaders[i], header);
            }

            for (int i = 0; i < 10; i++)
            {
                Assert.True(cache.TryGetHeader(rawHeaders[i], out var header));
                Assert.Equal(header, cache.Head);
                Assert.NotEqual(header, cache.Tail);
            }
        }

        [Fact]
        public void AddHeader_Parallel()
        {
            var cache = new JwtHeaderCache();
            var rawHeaders = new byte[1000][];
            for (int i = 0; i < 1000; i++)
            {
                rawHeaders[i] = new byte[32];
                RandomNumberGenerator.Fill(rawHeaders[i]);
            }

            var p = Parallel.For(0, 100, j =>
            {
                for (int i = 0; i < 1000; i++)
                {
                    cache.AddHeader(rawHeaders[i], new JwtHeader());
                }
            });

            Assert.True(cache.Validate());
            var p2 = Parallel.For(0, 100, j =>
            {
                for (int i = 0; i < 1000; i++)
                {
                    cache.TryGetHeader(rawHeaders[i], out var header);
                }
            });

            Assert.True(cache.Validate());
        }
    }
}
#endif