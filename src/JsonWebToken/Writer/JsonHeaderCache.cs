// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
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
            public Dictionary<int, byte[]> Entries;

            public Bucket? Next;

            public Bucket? Previous;

            public string Kid;

            public Bucket(string kid, Dictionary<int, byte[]> entries)
            {
                Kid = kid;
                Entries = entries;
            }
        }

        private SpinLock _spinLock = new SpinLock();

        /// <summary>
        /// The maximum size of the cache.
        /// </summary>
        public static int MaxSize { get; set; } = 10;

        private Bucket? _head = null;
        private Bucket? _tail = null;

        /// <summary>
        ///  Try to get the header.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="alg"></param>
        /// <param name="base64UrlHeader"></param>
        /// <returns></returns>
        public bool TryGetHeader(JwtHeader header, SignatureAlgorithm alg, [NotNullWhen(true)] out byte[]? base64UrlHeader)
        {
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
    }
}
