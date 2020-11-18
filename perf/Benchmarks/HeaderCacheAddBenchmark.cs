using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class HeaderCacheAddBenchmark
    {
        private readonly CircularJwtHeaderDocumentCache _circular = new CircularJwtHeaderDocumentCache();
        private readonly LruJwtHeaderDocumentCache _lru = new LruJwtHeaderDocumentCache();

        private readonly CircularJwtHeaderDocumentCache[] _circularArray = CreateCircularCacheArray(16);
        private readonly LruJwtHeaderDocumentCache[] _lruArray = CreateLruCacheArray(16);
                private readonly byte[] _data = new byte[64];

        [Benchmark(Baseline = false)]
        [Arguments(1)]
        [Arguments(16)]
        [Arguments(64)]
        [BenchmarkCategory("Add")]
        public void CircularCache_Add(int count)
        {
            _circular.Clear();
            for (int i = 0; i < count; i++)
            {
                _circular.AddHeader(_data, JwtHeaderDocument.Empty);
            }
        }

        [Benchmark(Baseline = true)]
        [Arguments(1)]
        [Arguments(16)]
        [Arguments(64)]
        [BenchmarkCategory("Add")]
        public void LruCache_Add(int count)
        {
            _lru.Clear();
            for (int i = 0; i < count; i++)
            {
                _lru.AddHeader(_data, JwtHeaderDocument.Empty);
            }
        }

        [Benchmark(Baseline = false)]
        [Arguments(0)]
        [Arguments(15)]
        [BenchmarkCategory("TryGet")]
        public JwtHeaderDocument? CircularCache_TryGet(int count)
        {
            var cache = _circularArray[count];

            cache.TryGetHeader(_data, out var header);
            return header;
        }

        [Benchmark(Baseline = true)]
        [Arguments(0)]
        [Arguments(15)]
        [BenchmarkCategory("TryGet")]
        public JwtHeaderDocument? LruCache_TryGet(int count)
        {
            var cache = _lruArray[count];

            cache.TryGetHeader(_data, out var header);
            return header;
        }

        private static byte[][] CreateData(int count, int size)
        {
            var data = new byte[count][];
            for (int i = 0; i < count; i++)
            {
                data[i] = new byte[size];
                using RandomNumberGenerator rnd = RandomNumberGenerator.Create();
                rnd.GetBytes(data[i]);
            }

            return data;
        }

        private static CircularJwtHeaderDocumentCache CreateCircularCache(int count, int size = 64)
        {
            CircularJwtHeaderDocumentCache cache = new CircularJwtHeaderDocumentCache();
            var data = CreateData(count, size);
            for (int i = 0; i < data.Length; i++)
            {
                cache.AddHeader(data[i], JwtHeaderDocument.Empty);
            }

            return cache;
        }

        private static CircularJwtHeaderDocumentCache[] CreateCircularCacheArray(int count, int size = 64)
        {
            var caches = new CircularJwtHeaderDocumentCache[count];
            for (int i = 0; i < count; i++)
            {
                caches[i] = CreateCircularCache(i, size);
            }

            return caches;
        }

        private static LruJwtHeaderDocumentCache CreateLruCache(int count, int size = 64)
        {
            LruJwtHeaderDocumentCache cache = new LruJwtHeaderDocumentCache();
            var data = CreateData(count, size);
            for (int i = 0; i < data.Length; i++)
            {
                cache.AddHeader(data[i], JwtHeaderDocument.Empty);
            }

            return cache;
        }

        private static LruJwtHeaderDocumentCache[] CreateLruCacheArray(int count, int size = 64)
        {
            var caches = new LruJwtHeaderDocumentCache[count];
            for (int i = 0; i < count; i++)
            {
                caches[i] = CreateLruCache(i, size);
            }

            return caches;
        }

        /// <summary>
        /// Represents a cache for <see cref="JwtHeaderDocument"/>.
        /// </summary>
        public sealed class CircularJwtHeaderDocumentCache : IJwtHeaderDocumentCache
        {
            private const int MaxItems = 16;
#if DEBUG
            static CircularJwtHeaderDocumentCache()
            {
                // TEST Debug.Assert(MaxItems % 2 == 0);
            }
#endif
            private readonly struct Node
            {
                public readonly JwtHeaderDocument Header;

                public readonly ReadOnlyMemory<byte> Key;

                public Node(ReadOnlyMemory<byte> key, JwtHeaderDocument header)
                {
                    Key = key;
                    Header = header;
                }
            }

            private int _index = 0;
            private readonly Node[] _nodes = new Node[MaxItems];

            /// <summary>
            /// The heade of the cache.
            /// </summary>
            public JwtHeaderDocument? Head => _nodes[_index & (MaxItems - 1)].Header;

            /// <inheritdoc/>
            public bool Enabled => true;

            /// <inheritdoc/>
            public bool TryGetHeader(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out JwtHeaderDocument? header)
            {
                int index = _index & (MaxItems - 1);
                for (int i = 0; i < MaxItems; i++)
                {
                    int idx = (index + i) & (MaxItems - 1);
                    var node = _nodes[idx];
                    if (buffer.SequenceEqual(node.Key.Span))
                    {
                        _index = idx;
                        header = node.Header;
                        goto Found;
                    }
                }

                header = null;
                return false;
            Found:
                return true;
            }

            /// <inheritdoc/>
            public void AddHeader(ReadOnlySpan<byte> rawHeader, JwtHeaderDocument header)
            {
                _index = (_index + 1) & (MaxItems - 1);
                _nodes[_index] = new Node(rawHeader.ToArray(), header.Clone());
            }


            /// <summary>
            /// Validate the integrity of the cache.
            /// </summary>
            /// <returns></returns>
            public bool Validate()
            {
                return true;
            }

            internal void Clear()
            {
                _index = 0;
            }
        }
    }
}
