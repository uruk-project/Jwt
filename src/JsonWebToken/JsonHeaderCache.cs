using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Threading;

namespace JsonWebToken
{
    public class JsonHeaderCache
    {
        private sealed class Bucket
        {
            public Dictionary<long, byte[]> Entries;

            public Bucket Next;

            public Bucket Previous;

            public string Kid;
        }

        private readonly object _syncLock = new object();
        private SpinLock _spinLock = new SpinLock();

        private int _count = 0;

        public static int MaxSize { get; set; } = 10;

        private Bucket _head = null;
        private Bucket _tail = null;

        public bool TryGetHeader(JObject header, in SignatureAlgorithm alg, out byte[] base64UrlHeader)
        {
            if (!IsSimpleHeader(header, alg))
            {
                base64UrlHeader = null;
                return false;
            }

            if (header.TryGetValue(HeaderParameters.Kid, out var kid))
            {
                var key = ComputeHeaderKey(header, alg);
                var keyId = ((string)kid).AsSpan();
                var node = _head;
                while (node != null)
                {
                    if (keyId.SequenceEqual(node.Kid.AsSpan()))
                    {
                        if (node.Entries.TryGetValue(key, out var entry))
                        {
                            base64UrlHeader = entry;
                            MoveToHead(node);
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

        private static long ComputeHeaderKey(JObject header, in SignatureAlgorithm alg)
        {
            header.TryGetValue(HeaderParameters.Cty, out JToken cty);

            if (alg == SignatureAlgorithm.Empty)
            {
                return -1;
            }
                       
            if (cty != null && !string.Equals(cty.Value<string>(), ContentTypeValues.Jwt, StringComparison.Ordinal))
            {
                return -1;
            }

            return (long)alg;
        }

        public void AddHeader(JObject header, in SignatureAlgorithm alg, ReadOnlySpan<byte> base6UrlHeader)
        {
            if (!header.TryGetValue(HeaderParameters.Kid, out var kid))
            {
                return;
            }

            if (!IsSimpleHeader(header, alg))
            {
                return;
            }

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

        private static bool IsSimpleHeader(JObject header, in SignatureAlgorithm alg)
        {
            if (!header.ContainsKey(HeaderParameters.Kid))
            {
                return false;
            }

            int simpleHeaders = 1;
            if (alg != default)
            {
                simpleHeaders++;
            }

            if (header.TryGetValue(HeaderParameters.Cty, out var cty))
            {
                if (cty.Type != JTokenType.Null && string.Equals(cty.Value<string>(), ContentTypeValues.Jwt, StringComparison.Ordinal))
                {
                    return false;
                }

                simpleHeaders++;
            }

            return header.Count == simpleHeaders;
        }

        private void MoveToHead(Bucket node)
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
    }
}
