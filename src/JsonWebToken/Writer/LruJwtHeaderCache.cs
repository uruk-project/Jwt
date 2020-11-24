// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>Represents a cache for JWT Header in JSON.</summary>
    internal sealed class LruJwtHeaderCache : IJwtHeaderCache
    {
        ///<summary>The maxium number of header in cache.</summary>
        public const int MaxSize = 16;

        internal void Clear()
        {
            _head = null;
            _tail = null;
            _count = 0;
        }

        private SpinLock _spinLock = new SpinLock();
        private int _count = 0;

        /// <summary>Gets the count of items in the cache.</summary>
        public int Count => _count;

        private Bucket? _head = null;
        private Bucket? _tail = null;
        private WrappedHeader _firstJwsHeader;
        private WrappedHeader _firstJweHeader;

        /// <summary>Try to get the header.</summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="kid"></param>
        /// <param name="typ"></param>
        /// <param name="base64UrlHeader"></param>
        /// <returns></returns>
        public bool TryGetHeader(JwtHeader header, SignatureAlgorithm alg, JsonEncodedText kid, string? typ, [NotNullWhen(true)] out byte[]? base64UrlHeader)
        {
            if (ReferenceEquals(_firstJwsHeader.Header, header))
            {
                base64UrlHeader = _firstJwsHeader.BinaryHeader;
                goto Found;
            }

            if (IsEligibleHeaderForJws(header.Count, kid, typ))
            {
                int algoritmId = (int)alg.Id;
                var node = _head;
                while (node != null)
                {
                    if (algoritmId == node.AlgorithmId)
                    {
                        if (node.TryGetEntry(kid, out var entry))
                        {
                            if (typ != entry.Typ)
                            {
                                goto NotFound;
                            }

                            base64UrlHeader = entry.Data;
                            if (node != _head)
                            {
                                MoveToHead(node);
                            }

                            goto Found;
                        }
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
        /// <param name="kid"></param>
        /// <param name="typ"></param>
        /// <param name="base6UrlHeader"></param>
        public void AddHeader(JwtHeader header, SignatureAlgorithm alg, JsonEncodedText kid, string? typ, ReadOnlySpan<byte> base6UrlHeader)
        {
            _firstJwsHeader = new WrappedHeader(header, base6UrlHeader.ToArray());
            if (IsEligibleHeaderForJws(header.Count, kid, typ))
            {
                int algorithmId = (int)alg.Id;
                bool lockTaken = false;
                try
                {
                    _spinLock.Enter(ref lockTaken);
                    if (_count >= MaxSize)
                    {
                        _head = null;
                        _tail = null;
                        _count = 0;
                    }

                    var node = _head;
                    while (node != null)
                    {
                        if (algorithmId == node.AlgorithmId)
                        {
                            break;
                        }

                        node = node.Next;
                    }

                    var key = alg.Id;
                    if (node is null)
                    {
                        _count++;
                        node = new Bucket(algorithmId, new Dictionary<JsonEncodedText, CacheEntry>(1) { { kid, new CacheEntry(base6UrlHeader.ToArray(), typ) } })
                        {
                            Next = _head
                        };
                    }
                    else
                    {
                        if (!node.Entries.ContainsKey(kid))
                        {
                            _count++;
                            node.Entries[kid] = new CacheEntry(base6UrlHeader.ToArray(), typ);
                        }
                    }

                    if (!ReferenceEquals(_head, node))
                    {
                        if (_head != null)
                        {
                            _head.Previous = node;
                        }

                        _head = node;
                    }

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

        /// <summary>
        /// Validate the integrity of the cache.
        /// </summary>
        /// <returns></returns>
        public bool Validate()
        {
            var head = _head;
            while (head != null)
            {
                var previous = head;
                head = head.Next;
                if (head != null && !ReferenceEquals(head.Previous, previous))
                {
                    goto Invalid;
                }
            }

            head = _tail;
            while (head != null)
            {
                var next = head;
                head = head.Previous;
                if (head != null && head.Next != next)
                {
                    goto Invalid;
                }
            }

            return true;

        Invalid:
            return false;
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

        /// <inheritdoc/>
        public void AddHeader(JwtHeader header, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, JsonEncodedText kid, string? typ, string? cty, ReadOnlySpan<byte> base6UrlHeader)
        {
            _firstJweHeader = new WrappedHeader(header, base6UrlHeader.ToArray());
            if (IsEligibleHeaderForJwe(header.Count, kid, typ, cty))
            {
                int algorithmId = enc.ComputeKey(alg);
                bool lockTaken = false;
                try
                {
                    _spinLock.Enter(ref lockTaken);
                    if (_count >= MaxSize)
                    {
                        _head = null;
                        _tail = null;
                        _count = 0;
                    }

                    var node = _head;
                    while (node != null)
                    {
                        if (algorithmId == node.AlgorithmId)
                        {
                            break;
                        }

                        node = node.Next;
                    }

                    var key = alg.Id;
                    if (node is null)
                    {
                        _count++;
                        node = new Bucket(algorithmId, new Dictionary<JsonEncodedText, CacheEntry>(1) { { kid, new CacheEntry(base6UrlHeader.ToArray(), typ, cty) } })
                        {
                            Next = _head
                        };
                    }
                    else
                    {
                        if (!node.Entries.ContainsKey(kid!))
                        {
                            _count++;
                            node.Entries[kid] = new CacheEntry(base6UrlHeader.ToArray(), typ);
                        }
                    }

                    if (!ReferenceEquals(_head, node))
                    {
                        if (_head != null)
                        {
                            _head.Previous = node;
                        }

                        _head = node;
                    }

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

        /// <inheritdoc/>
        public bool TryGetHeader(JwtHeader header, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, JsonEncodedText kid, string? typ, string? cty, [NotNullWhen(true)] out byte[]? base64UrlHeader)
        {
            if (ReferenceEquals(_firstJweHeader.Header, header))
            {
                base64UrlHeader = _firstJweHeader.BinaryHeader;
                goto Found;
            }

            if (IsEligibleHeaderForJwe(header.Count, kid, typ, cty))
            {
                int algorithmId = enc.ComputeKey(alg);
                var node = _head;
                while (node != null)
                {
                    if (algorithmId == node.AlgorithmId)
                    {
                        if (node.TryGetEntry(kid, out var entry))
                        {
                            if (cty != entry.Cty)
                            {
                                goto NotFound;
                            }

                            if (typ != entry.Typ)
                            {
                                goto NotFound;
                            }

                            base64UrlHeader = entry.Data;
                            if (node != _head)
                            {
                                MoveToHead(node);
                            }

                            goto Found;
                        }
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsEligibleHeaderForJws(int count, JsonEncodedText kid, string? typ)
        {
            return kid.EncodedUtf8Bytes.Length != 0 && count <= (typ is null ? 2 : 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsEligibleHeaderForJwe(int count, JsonEncodedText kid, string? typ, string? cty)
        {
            bool eligible = kid.EncodedUtf8Bytes.Length != 0;
            if (eligible)
            {
                int maxHeaderCount = 3; // alg + enc + kid
                if (typ != null)
                {
                    maxHeaderCount++;
                }

                if (cty != null)
                {
                    maxHeaderCount++;
                }

                eligible = count <= maxHeaderCount;
            }

            return eligible;
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

        private sealed class CacheEntry
        {
            public string? Typ;
            public string? Cty;
            public byte[] Data;

            public CacheEntry(byte[] data, string? typ)
            {
                Data = data;
                Typ = typ;
            }

            public CacheEntry(byte[] data, string? typ, string? cty)
            {
                Data = data;
                Typ = typ;
                Cty = cty;
            }
        }

        private sealed class Bucket
        {
            public readonly Dictionary<JsonEncodedText, CacheEntry> Entries;
            public readonly int AlgorithmId;

            public KeyValuePair<JsonEncodedText, CacheEntry> LatestEntry;
            public Bucket? Next;
            public Bucket? Previous;

            public Bucket(int algorithmId, Dictionary<JsonEncodedText, CacheEntry> entries)
            {
                AlgorithmId = algorithmId;
                Entries = entries;
                LatestEntry = default;
            }

            public bool TryGetEntry(JsonEncodedText kid, [NotNullWhen(true)] out CacheEntry? entry)
            {
                // Fast path. Try to avoid the lookup to the dictionary 
                // as we should only have 1 entry
                if (LatestEntry.Key.Equals(kid))
                {
                    entry = LatestEntry.Value;
                    return true;
                }

                return Entries.TryGetValue(kid, out entry);
            }
        }
    }
}
