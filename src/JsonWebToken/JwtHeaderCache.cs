using System;
using System.Threading;

namespace JsonWebToken
{
    public class JwtHeaderCache
    {
        private class Node
        {
            public JwtHeader Header;

            public Node Next;

            public Node Previous;

            public byte[] Key;
        }

        private readonly object _syncLock = new object();
        private SpinLock _spinLock = new SpinLock();

        private int _count = 0;

        public int MaxSize { get; set; } = 10;

        private Node _head = null;
        private Node _tail = null;

        public JwtHeader Head => _head.Header;

        public JwtHeader Tail => _tail.Header;

        public bool TryGetHeader(ReadOnlySpan<byte> buffer, out JwtHeader header)
        {
            var node = _head;
            while (node != null)
            {
                if (buffer.SequenceEqual(node.Key))
                {
                    header = node.Header;
                    MoveToHead(node);
                    return true;
                }

                node = node.Next;
            }

            header = null;
            return false;
        }

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
            if (node != _head)
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
                            node.Next.Previous = node.Previous;
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
        }

        private void RemoveLeastRecentlyUsed()
        {
            var node = _tail;
            node.Previous.Next = null;
            _tail = node.Previous;
        }

        public bool Validate()
        {
            var node = _head;
            while (node != null)
            {
                var previous = node;
                node = node.Next;
                if (node != null && node.Previous != previous)
                {
                    return false;
                }
            }

            node = _tail;
            while (node != null)
            {
                var next = node;
                node = node.Previous;
                if (node != null && node.Next != next)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
