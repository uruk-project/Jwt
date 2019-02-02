// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Threading;

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

            public Bucket Next;

            public Bucket Previous;

            public string Kid;
        }

        private SpinLock _spinLock = new SpinLock();

        private int _count = 0;

        /// <summary>
        /// The maximum size of the cache.
        /// </summary>
        public static int MaxSize { get; set; } = 10;

        private Bucket _head = null;
        private Bucket _tail = null;

        /// <summary>
        ///  Try to get the header.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="base64UrlHeader"></param>
        /// <returns></returns>
        public bool TryGetHeader(JwtObject header, SignatureAlgorithm alg, out byte[] base64UrlHeader)
        {
            if (!IsSimpleHeader(header, alg))
            {
                base64UrlHeader = null;
                return false;
            }

            if (header.TryGetValue(HeaderParameters.KidUtf8, out var kidProperty) && kidProperty.Type == JwtTokenType.String)
            {
                var key = ComputeHeaderKey(header, alg);
                if (key == -1)
                {
                    base64UrlHeader = null;
                    return false;
                }

                var kid = (string)kidProperty.Value;
                var keyId = kid.AsSpan();
                var node = _head;
                while (node != null)
                {
                    if (keyId.SequenceEqual(node.Kid.AsSpan()))
                    {
                        if (node.Entries.TryGetValue(key, out var entry))
                        {
                            base64UrlHeader = entry;
                            if (node != _head)
                            {
                                MoveToHead(node);
                            }

                            return true;
                        }

                        base64UrlHeader = null;
                        return false;
                    }

                    node = node.Next;
                }
            }

            base64UrlHeader = null;
            return false;
        }

        private static long ComputeHeaderKey(JwtObject header, SignatureAlgorithm alg)
        {
            header.TryGetValue(HeaderParameters.CtyUtf8, out var cty);
            if (alg is null)
            {
                return -1;
            }

            if (cty.Type == JwtTokenType.String && !string.Equals((string)cty.Value, ContentTypeValues.Jwt, StringComparison.Ordinal))
            {
                // only support 'cty': 'JWT' or not cty
                return -1;
            }

            return alg;
        }

        /// <summary>
        /// Adds a base64url encoded header to the cache.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="base6UrlHeader"></param>
        public void AddHeader(JwtObject header, SignatureAlgorithm alg, ReadOnlySpan<byte> base6UrlHeader)
        {
            if (!header.TryGetValue(HeaderParameters.KidUtf8, out var kidProperty) && kidProperty.Type == JwtTokenType.String)
            {
                return;
            }

            if (!IsSimpleHeader(header, alg))
            {
                return;
            }

            var kid = (string)kidProperty.Value;
            bool lockTaken = false;
            try
            {
                _spinLock.Enter(ref lockTaken);

                var node = _head;
                while (node != null)
                {
                    if (string.Equals(node.Kid, (string)kid, StringComparison.Ordinal))
                    {
                        break;
                    }

                    node = node.Next;
                }

                var key = ComputeHeaderKey(header, alg);
                if (key == -1)
                {
                    return;
                }

                if (node == null)
                {
                    node = new Bucket
                    {
                        Kid = (string)kid,
                        Next = _head,
                        Entries = new Dictionary<long, byte[]>(1) { { key, base6UrlHeader.ToArray() } }
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
                if (_tail == null)
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

        private static bool IsSimpleHeader(JwtObject header, SignatureAlgorithm alg)
        {
            if (!header.ContainsKey(HeaderParameters.KidUtf8))
            {
                return false;
            }

            int simpleHeaders = 1;
            if (!(alg is null))
            {
                simpleHeaders++;
            }

            if (header.TryGetValue(HeaderParameters.CtyUtf8, out var cty))
            {
                if (cty.Type == JwtTokenType.String && string.Equals((string)cty.Value, ContentTypeValues.Jwt, StringComparison.Ordinal))
                {
                    return false;
                }

                simpleHeaders++;
            }

            return header.Count == simpleHeaders;
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
                    node.Next.Previous = node.Previous;
                }

                node.Previous.Next = node.Next;
                node.Next = _head;
                node.Previous = null;
                _head = node;
            }
        }

        private void RemoveLeastRecentlyUsed()
        {
            var node = _tail;
            node.Previous.Next = null;
            _tail = node.Previous;
        }
    }
}
