﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a cache for JWT Header in JSON.
    /// </summary>
    public sealed class JsonHeaderCache
    {
        private sealed class Bucket
        {
            public Dictionary<long, byte[]> Entries;

            public Bucket? Next;

            public Bucket? Previous;

            public string Kid;

            public Bucket(string kid, Dictionary<long, byte[]> entries)
            {
                Kid = kid;
                Entries = entries;
            }
        }

        private SpinLock _spinLock = new SpinLock();

        private int _count = 0;

        /// <summary>
        /// The maximum size of the cache.
        /// </summary>
        public static int MaxSize { get; set; } = 10;

        private Bucket? _head = null;
        private Bucket? _tail = null;
        private WrappedHeader _firstHeader;

        /// <summary>
        ///  Try to get the header.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="base64UrlHeader"></param>
        /// <returns></returns>
        public bool TryGetHeader(JwtObject header, SignatureAlgorithm alg, [NotNullWhen(true)] out byte[]? base64UrlHeader)
        {
            // fast-path: the header reference is already known. Do not care of the 'alg'
            var last = _firstHeader;
            if (ReferenceEquals(last.Header, header))
            {
                base64UrlHeader = last.BinaryHeader;
                return true;
            }

            if (header.TryGetValue(HeaderParameters.KidUtf8, out var kidProperty)
                && kidProperty.Type == JwtTokenType.String
                && !(kidProperty.Value is null)
                && !(alg is null)
                && header.Count == 2)
            {
                var kid = (string)kidProperty.Value;
                var keyId = kid.AsSpan();
                var node = _head;
                while (node != null)
                {
                    if (keyId.SequenceEqual(node.Kid.AsSpan()))
                    {
                        if (node.Entries.TryGetValue(alg.Id, out var entry))
                        {
                            base64UrlHeader = entry;
                            if (node != _head)
                            {
                                MoveToHead(node);
                            }

                            return true;
                        }

                        goto NotFound;
                    }

                    node = node.Next;
                }
            }

        NotFound:
            base64UrlHeader = null;
            return false;
        }

        /// <summary>
        /// Adds a base64url encoded header to the cache.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="base6UrlHeader"></param>
        public void AddHeader(JwtObject header, SignatureAlgorithm alg, ReadOnlySpan<byte> base6UrlHeader)
        {
            if (_firstHeader.Header is null)
            {
                // concurrency issue: the first cached header may not be the first, but it does not matter
                _firstHeader = new WrappedHeader(header, base6UrlHeader.ToArray());
                _count++;
            }
            else
            {
                if (header.TryGetValue(HeaderParameters.KidUtf8, out var kidProperty)
                    && kidProperty.Type == JwtTokenType.String
                    && !(kidProperty.Value is null)
                    && !(alg is null)
                    && header.Count == 2)
                {
                    var kid = (string)kidProperty.Value;
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
                            node = new Bucket(kid, new Dictionary<long, byte[]>(1) { { key, base6UrlHeader.ToArray() } })
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
            public readonly JwtObject? Header;
            public readonly byte[] BinaryHeader;

            public WrappedHeader(JwtObject header, byte[] binaryHeader)
            {
                Header = header;
                BinaryHeader = binaryHeader;
            }
        }
    }
}
