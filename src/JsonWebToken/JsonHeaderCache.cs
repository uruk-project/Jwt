using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Threading;

namespace JsonWebToken
{
    public class JsonHeaderCache
    {
        private class Bucket
        {
            public Dictionary<int, byte[]> Entries;

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

        public bool TryGetHeader(JObject header, out byte[] base64UrlHeader)
        {
            if (!IsSimmpleHeader(header))
            {
                base64UrlHeader = null;
                return false;
            }

            if (header.TryGetValue(HeaderParameters.Kid, out var kid))
            {
                var key = ComputeHeaderKey(header);
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

        private int ComputeHeaderKey(JObject header)
        {
            JToken alg, enc, cty;
            header.TryGetValue(HeaderParameters.Alg, out alg);
            header.TryGetValue(HeaderParameters.Enc, out enc);
            header.TryGetValue(HeaderParameters.Cty, out cty);

            int key = 0;
            if (alg != null)
            {
                switch (alg.Value<string>())
                {
                    case SignatureAlgorithms.HmacSha256:
                        key = 1;
                        break;
                    case SignatureAlgorithms.HmacSha384:
                        key = 2;
                        break;
                    case SignatureAlgorithms.HmacSha512:
                        key = 3;
                        break;
                    case SignatureAlgorithms.RsaSha256:
                        key = 4;
                        break;
                    case SignatureAlgorithms.RsaSha384:
                        key = 5;
                        break;
                    case SignatureAlgorithms.RsaSha512:
                        key = 6;
                        break;
                    case SignatureAlgorithms.RsaSsaPssSha256:
                        key = 7;
                        break;
                    case SignatureAlgorithms.RsaSsaPssSha384:
                        key = 8;
                        break;
                    case SignatureAlgorithms.RsaSsaPssSha512:
                        key = 9;
                        break;
                    case SignatureAlgorithms.EcdsaSha256:
                        key = 10;
                        break;
                    case SignatureAlgorithms.EcdsaSha384:
                        key = 11;
                        break;
                    case SignatureAlgorithms.EcdsaSha512:
                        key = 12;
                        break;

                    case KeyManagementAlgorithms.Aes128KW:
                        key = 13;
                        break;
                    case KeyManagementAlgorithms.Aes192KW:
                        key = 14;
                        break;
                    case KeyManagementAlgorithms.Aes256KW:
                        key = 15;
                        break;
                    case KeyManagementAlgorithms.Direct:
                        key = 16;
                        break;
                    case KeyManagementAlgorithms.RsaOaep:
                        key = 17;
                        break;
                    case KeyManagementAlgorithms.RsaOaep256:
                        key = 18;
                        break;
                    case KeyManagementAlgorithms.RsaPkcs1:
                        key = 19;
                        break;

                    default:
                        return -1;
                }
            }

            key <<= 8;
            if (enc != null)
            {
                switch (enc.Value<string>())
                {
                    case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                        key |= 1;
                        break;
                    case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                        key |= 2;
                        break;
                    case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                        key |= 3;
                        break;
                    default:
                        return -1;
                }
            }

            if (cty != null && !string.Equals(cty.Value<string>(), ContentTypeValues.Jwt, StringComparison.Ordinal))
            {
                return -1;
            }

            return key;
        }

        public void AddHeader(JObject header, ReadOnlySpan<byte> base6UrlHeader)
        {
            if (!header.TryGetValue(HeaderParameters.Kid, out var kid))
            {
                return;
            }

            if (!IsSimmpleHeader(header))
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

                var key = ComputeHeaderKey(header);
                if (node == null)
                {
                    node = new Bucket
                    {
                        Kid = (string)kid,
                        Next = _head,
                        Entries = new Dictionary<int, byte[]> { { key, base6UrlHeader.ToArray() } }
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

        private bool IsSimmpleHeader(JObject header)
        {
            if (!header.ContainsKey(HeaderParameters.Kid))
            {
                return false;
            }

            int simpleHeaders = 1;
            if (header.ContainsKey(HeaderParameters.Alg))
            {
                simpleHeaders++;
            }

            if (header.ContainsKey(HeaderParameters.Enc))
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
