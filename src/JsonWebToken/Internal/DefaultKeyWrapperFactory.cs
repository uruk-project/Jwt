using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    public class DefaultKeyWrapperFactory : IKeyWrapperFactory, IDisposable
    {
        private readonly ConcurrentDictionary<ProviderFactoryKey, KeyWrapper> _keyWrappers = new ConcurrentDictionary<ProviderFactoryKey, KeyWrapper>(JwkEqualityComparer.Default);
        private bool _disposed;

        public virtual KeyWrapper Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            if (encryptionAlgorithm == null || contentEncryptionAlgorithm == null)
            {
                return null;
            }

            var algorithmKey = (encryptionAlgorithm.Id << 8) | (byte)contentEncryptionAlgorithm.Id;
            var factoryKey = new ProviderFactoryKey(key, algorithmKey);
            if (_keyWrappers.TryGetValue(factoryKey, out var cachedKeyWrapper))
            {
                return cachedKeyWrapper;
            }

            if (key.IsSupported(contentEncryptionAlgorithm))
            {
                var keyWrapper = key.CreateKeyWrapper(encryptionAlgorithm, contentEncryptionAlgorithm);
                if (!_keyWrappers.TryAdd(factoryKey, keyWrapper) && _keyWrappers.TryGetValue(factoryKey, out cachedKeyWrapper))
                {
                    keyWrapper.Dispose();
                    return cachedKeyWrapper;
                }
                else
                {
                    return keyWrapper;
                }
            }

            return null;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    foreach (var keyWrapper in _keyWrappers)
                    {
                        keyWrapper.Value.Dispose();
                    }
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
    }
}