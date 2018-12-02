// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    public sealed class CryptographicStore<TCrypto> : IDisposable where TCrypto : IDisposable
    {
        private readonly ConcurrentDictionary<CryptographicFactoryKey, TCrypto> _store;
        private bool _disposed;

        public CryptographicStore()
        {
            _store = new ConcurrentDictionary<CryptographicFactoryKey, TCrypto>(JwkEqualityComparer.Default);
        }

        public bool TryGetValue(CryptographicFactoryKey key, out TCrypto value)
        {
            return _store.TryGetValue(key, out value);
        }

        public TCrypto AddValue(CryptographicFactoryKey key, TCrypto value)
        {
            if (!_store.TryAdd(key, value) && _store.TryGetValue(key, out var cachedValue))
            {
                value.Dispose();
                return cachedValue;
            }
            else
            {
                return value;
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                foreach (var item in _store)
                {
                    item.Value.Dispose();
                }

                _disposed = true;
            }
        }
    }
}