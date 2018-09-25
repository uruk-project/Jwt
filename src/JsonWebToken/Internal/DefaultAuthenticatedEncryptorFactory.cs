using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    public class DefaultAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory, IDisposable
    {
        private readonly ConcurrentDictionary<ProviderFactoryKey, AuthenticatedEncryptor> _encryptors = new ConcurrentDictionary<ProviderFactoryKey, AuthenticatedEncryptor>(JwkEqualityComparer.Default);

        private bool _disposed;

        public virtual AuthenticatedEncryptor Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var factoryKey = new ProviderFactoryKey(key, encryptionAlgorithm.Id);
            if (_encryptors.TryGetValue(factoryKey, out var cachedEncryptor))
            {
                return cachedEncryptor;
            }

            if (key.IsSupported(encryptionAlgorithm))
            {
                var encryptor = key.CreateAuthenticatedEncryptor(encryptionAlgorithm);

                if (!_encryptors.TryAdd(factoryKey, encryptor) && _encryptors.TryGetValue(factoryKey, out cachedEncryptor))
                {
                    encryptor.Dispose();
                    return cachedEncryptor;
                }
                else
                {
                    return encryptor;
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
                    foreach (var encryptor in _encryptors)
                    {
                        encryptor.Value.Dispose();
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