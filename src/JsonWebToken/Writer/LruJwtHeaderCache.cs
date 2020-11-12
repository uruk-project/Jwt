// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>Represents a cache for JWT Header in JSON.</summary>
    public sealed class LruJwtHeaderCache : IJwtHeaderCache
    {
        private sealed class Bucket
        {
            public readonly Dictionary<int, byte[]> Entries;

            public KeyValuePair<int, byte[]> LatestEntry;

            public Bucket? Next;

            public Bucket? Previous;

            public string Kid;

            public Bucket(string kid, Dictionary<int, byte[]> entries)
            {
                Kid = kid;
                Entries = entries;
                LatestEntry = default;
            }

            public bool TryGetEntry(int key, [NotNullWhen(true)] out byte[]? entry)
            {
                // Fast path. Try to avoid the lookup to the dictionary 
                // as we should only have 1 entry
                if (LatestEntry.Key == key)
                {
                    entry = LatestEntry.Value;
                    return true;
                }

                return Entries.TryGetValue(key, out entry);
            }
        }

        private SpinLock _spinLock = new SpinLock();
        private int _count = 0;

        /// <summary>The maximum size of the cache.</summary>
        public static int MaxSize { get; set; } = 10;

        private Bucket? _head = null;
        private Bucket? _tail = null;
        private WrappedHeader _firstHeader;

        /// <summary>Try to get the header.</summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="base64UrlHeader"></param>
        /// <returns></returns>
        public bool TryGetHeader(JwtHeader header, SignatureAlgorithm alg, [NotNullWhen(true)] out byte[]? base64UrlHeader)
        {
            if (ReferenceEquals(_firstHeader.Header, header))
            {
                base64UrlHeader = _firstHeader.BinaryHeader;
                goto Found;
            }

            if (header.TryGetValue(HeaderParameters.Kid, out var kidProperty)
                && kidProperty.Type == JsonValueKind.String
                && !(kidProperty.Value is null)
                && !(alg is null)
                && header.Count == 2)
            {
                var kid = (string)kidProperty.Value;
                var node = _head;
                while (node != null)
                {
                    if (kid == node.Kid)
                    {
                        if (node.TryGetEntry(alg.Id, out var entry))
                        {
                            base64UrlHeader = entry;
                            if (node != _head)
                            {
                                MoveToHead(node);
                            }

                            goto Found;
                        }

                        goto NotFound;
                    }

                    node = node.Next;
                }
            }

        NotFound:
            base64UrlHeader = null;
            return false;

        Found:
            return true;
        }

        /// <summary>Adds a base64-url encoded header to the cache.</summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="base6UrlHeader"></param>
        public void AddHeader(JwtHeader header, SignatureAlgorithm alg, ReadOnlySpan<byte> base6UrlHeader)
        {
            if (_firstHeader.Header is null)
            {
                // concurrency issue: the first cached header may not be the first, but it does not matter
                _firstHeader = new WrappedHeader(header, base6UrlHeader.ToArray());
                _count++;
            }
            else
            {
                if (header.TryGetValue(HeaderParameters.Kid, out var kidProperty)
                    && kidProperty.Type == JsonValueKind.String
                    && header.Count == 2)
                {
                    var kid = (string)kidProperty.Value!;
                    bool lockTaken = false;
                    try
                    {
                        _spinLock.Enter(ref lockTaken);

                        var node = _head;
                        while (node != null)
                        {
                            if (string.Equals(node.Kid, kid, StringComparison.Ordinal))
                            {
                                break;
                            }

                            node = node.Next;
                        }

                        var key = alg.Id;
                        if (node is null)
                        {
                            node = new Bucket(kid, new Dictionary<int, byte[]>(1) { { key, base6UrlHeader.ToArray() } })
                            {
                                Next = _head
                            };
                        }
                        else
                        {
                            if (node.Entries.ContainsKey(key))
                            {
                                node.Entries[key] = base6UrlHeader.ToArray();
                            }
                        }

                        if (_count >= MaxSize)
                        {
                            RemoveLeastRecentlyUsed();
                        }
                        else
                        {
                            _count++;
                        }

                        if (_head != null)
                        {
                            _head.Previous = node;
                        }

                        _head = node;
                        if (_tail is null)
                        {
                            _tail = node;
                        }
                    }
                    finally
                    {
                        if (lockTaken)
                        {
                            _spinLock.Exit();
                        }
                    }
                }
            }
        }

        private void MoveToHead(Bucket node)
        {
            bool lockTaken = false;
            try
            {
                _spinLock.Enter(ref lockTaken);
                MoveToHeadLocked(node);
            }
            finally
            {
                if (lockTaken)
                {
                    _spinLock.Exit();
                }
            }
        }

        private void MoveToHeadLocked(Bucket node)
        {
            if (node != _head)
            {
                if (_head != null)
                {
                    _head.Previous = node;
                }

                if (node == _tail)
                {
                    _tail = node.Previous;
                }
                else
                {
                    if (node.Next != null)
                    {
                        node.Next.Previous = node.Previous;
                    }
                }

                if (node.Previous != null)
                {
                    node.Previous.Next = node.Next;
                }

                node.Next = _head;
                node.Previous = null;
                _head = node;
            }
        }

        private void RemoveLeastRecentlyUsed()
        {
            var node = _tail;
            if (node != null)
            {
                if (node.Previous != null)
                {
                    node.Previous.Next = null;
                }

                _tail = node.Previous;
            }
        }

        private readonly struct WrappedHeader
        {
            public readonly JwtHeader? Header;
            public readonly byte[] BinaryHeader;

            public WrappedHeader(JwtHeader header, byte[] binaryHeader)
            {
                Header = header;
                BinaryHeader = binaryHeader;
            }
        }
    }
}
