// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a cache for <see cref="JwtHeaderDocument"/>.
    /// </summary>
    public sealed class LruJwtHeaderDocumentCache : IJwtHeaderDocumentCache
    {
        private const int MaxSize = 16;

        private sealed class Node
        {
            public JwtHeaderDocument Header;

            public Node? Next;

            public Node? Previous;

            public byte[] Key;

            public Node(byte[] key, JwtHeaderDocument header, Node? next)
            {
                Key = key;
                Header = header;
                Next = next;
            }
        }

        private SpinLock _spinLock = new SpinLock();

        private int _count = 0;

        private Node? _head = null;
        private Node? _tail = null;

        /// <summary>
        /// The heade of the cache.
        /// </summary>
        public JwtHeaderDocument? Head => _head?.Header;

        /// <summary>
        /// The tail of the cache.
        /// </summary>
        public JwtHeaderDocument? Tail => _tail?.Header;

        /// <inheritdoc/>
        public bool Enabled => true;

        /// <inheritdoc/>
        public bool TryGetHeader(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out JwtHeaderDocument? header)
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

        /// <inheritdoc/>
        public void AddHeader(ReadOnlySpan<byte> rawHeader, JwtHeaderDocument header)
        {
            bool lockTaken = false;
            try
            {
                _spinLock.Enter(ref lockTaken);
                var node = new Node(rawHeader.ToArray(), header.Clone(), _head);
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

        /// <summary>
        /// Clear the cache.
        /// </summary>
        public void Clear()
        {
            _head = null;
            _tail = null;
            _count = 0;
        }
    }
}
