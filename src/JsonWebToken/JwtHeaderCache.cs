// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a cache for <see cref="JwtHeader"/>.
    /// </summary>
    public sealed class JwtHeaderCache
    {
        private sealed class Node
        {
            public JwtHeader Header;

            public Node Next;

            public Node Previous;

            public byte[] Key;
        }

        private SpinLock _spinLock = new SpinLock();

        private int _count = 0;

        /// <summary>
        /// The maximum size of the cache. 
        /// </summary>
        public int MaxSize { get; set; } = 10;

        private Node _head = null;
        private Node _tail = null;

        /// <summary>
        /// The heade of the cache.
        /// </summary>
        public JwtHeader Head => _head.Header;

        /// <summary>
        /// The tail of the cache.
        /// </summary>
        public JwtHeader Tail => _tail.Header;

        /// <summary>
        /// Try to get the <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="header"></param>
        /// <returns></returns>
        public bool TryGetHeader(ReadOnlySpan<byte> buffer, out JwtHeader header)
        {
            var node = _head;
            while (node != null)
            {
                if (buffer.SequenceEqual(node.Key))
                {
                    header = node.Header;
                    if (node != _head)
                    {
                        MoveToHead(node);
                    }

                    return true;
                }

                node = node.Next;
            }

            header = null;
            return false;
        }

        /// <summary>
        /// Adds the <see cref="JwtHeader"/> to the cache.
        /// </summary>
        /// <param name="rawHeader"></param>
        /// <param name="header"></param>
        public void AddHeader(ReadOnlySpan<byte> rawHeader, JwtHeader header)
        {
            var node = new Node
            {
                Key = rawHeader.ToArray(),
                Header = header,
                Next = _head
            };

            bool lockTaken = false;
            try
            {
                _spinLock.Enter(ref lockTaken);
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

        private void MoveToHead(Node node)
        {
            bool lockTaken = false;
            try
            {
                _spinLock.Enter(ref lockTaken);
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

                    node.Previous.Next = node.Next;
                    node.Next = _head;
                    node.Previous = null;
                    _head = node;
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

        private void RemoveLeastRecentlyUsed()
        {
            var node = _tail;
            node.Previous.Next = null;
            _tail = node.Previous;
        }

        /// <summary>
        /// Validate the integrity of the cache.
        /// </summary>
        /// <returns></returns>
        public bool Validate()
        {
            var node = _head;
            while (node != null)
            {
                var previous = node;
                node = node.Next;
                if (node != null && node.Previous != previous)
                {
                    goto Invalid;
                }
            }

            node = _tail;
            while (node != null)
            {
                var next = node;
                node = node.Previous;
                if (node != null && node.Next != next)
                {
                    goto Invalid;
                }
            }

            return true;

        Invalid:
            return false;
        }
    }
}
