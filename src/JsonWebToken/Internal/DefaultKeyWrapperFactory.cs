using System;

namespace JsonWebToken
{
    public class DefaultKeyWrapperFactory : IKeyWrapperFactory
    {
        private readonly CryptographicStore< KeyWrapper> _keyWrappers = new CryptographicStore<KeyWrapper>();
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
            var factoryKey = new CryprographicFactoryKey(key, algorithmKey);
            if (_keyWrappers.TryGetValue(factoryKey, out var cachedKeyWrapper))
            {
                return cachedKeyWrapper;
            }

            if (key.IsSupported(contentEncryptionAlgorithm))
            {
                var keyWrapper = key.CreateKeyWrapper(encryptionAlgorithm, contentEncryptionAlgorithm);
                return _keyWrappers.AddValue(factoryKey, keyWrapper);
            }

            return null;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _keyWrappers.Dispose();
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        void IDisposable.Dispose()
        {
            Dispose();
        }
    }
}