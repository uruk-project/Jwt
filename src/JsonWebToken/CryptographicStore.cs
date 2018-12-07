// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a store of cryptographics objects.
    /// </summary>
    /// <typeparam name="TCrypto"></typeparam>
    public sealed class CryptographicStore<TCrypto> : IDisposable where TCrypto : IDisposable
    {
        private readonly ConcurrentDictionary<CryptographicFactoryKey, TCrypto> _store;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicStore{TCrypto}"/> class.
        /// </summary>
        public CryptographicStore()
        {
            _store = new ConcurrentDictionary<CryptographicFactoryKey, TCrypto>(JwkEqualityComparer.Default);
        }

        /// <summary>
        /// Tries to get a <typeparamref name="TCrypto"/> for a given key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetValue(CryptographicFactoryKey key, out TCrypto value)
        {
            return _store.TryGetValue(key, out value);
        }

        /// <summary>
        /// Adds a <typeparamref name="TCrypto"/> to the store.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Release the managed resources.
        /// </summary>
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