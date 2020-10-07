// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a cache for <see cref="JwtHeader"/>.
    /// </summary>
    public sealed class JwtHeaderCache : IJwtHeaderCache
    {
        private sealed class Node
        {
            public JwtHeader Header;

            public Node? Next;

            public Node? Previous;

            public byte[] Key;

            public Node(byte[] key, JwtHeader header, Node? next)
            {
                Key = key;
                Header = header;
                Next = next;
            }
        }

        private SpinLock _spinLock = new SpinLock();

        private int _count = 0;

        /// <summary>
        /// The maximum size of the cache. 
        /// </summary>
        public int MaxSize { get; set; } = 10;

        private Node? _head = null;
        private Node? _tail = null;
        private readonly bool _enabled;

        /// <summary>
        /// The heade of the cache.
        /// </summary>
        public JwtHeader? Head => _head?.Header;

        /// <summary>
        /// The tail of the cache.
        /// </summary>
        public JwtHeader? Tail => _tail?.Header;

        /// <summary>
        /// Gets or sets whether the cache is enabled. <c>false</c> by default.
        /// </summary>
        public bool Enabled => _enabled;

        /// <summary>
        /// Try to get the <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="header"></param>
        /// <returns></returns>
        public bool TryGetHeader(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out JwtHeader? header)
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
            bool lockTaken = false;
            try
            {
                _spinLock.Enter(ref lockTaken);
                var node = new Node(rawHeader.ToArray(), header, _head);
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

        private void MoveToHead(Node node)
        {
            bool lockTaken = false;
            try
            {
                _spinLock.Enter(ref lockTaken);
                var head = _head;
                if (node != head)
                {
                    if (head != null)
                    {
                        head.Previous = node;
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

                    node.Next = head;
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
            var tail = _tail;
            if (tail != null)
            {
                var previous = tail.Previous;
                if (previous != null)
                {
                    previous.Next = null;
                }

                _tail = previous;
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
    }
}
