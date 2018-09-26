using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    public class DefaultAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
    {
        private readonly CryptographicStore<AuthenticatedEncryptor> _encryptors = new CryptographicStore<AuthenticatedEncryptor>();

        private bool _disposed;

        public virtual AuthenticatedEncryptor Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var factoryKey = new CryprographicFactoryKey(key, encryptionAlgorithm.Id);
            if (_encryptors.TryGetValue(factoryKey, out var cachedEncryptor))
            {
                return cachedEncryptor;
            }

            if (key.IsSupported(encryptionAlgorithm))
            {
                var encryptor = key.CreateAuthenticatedEncryptor(encryptionAlgorithm);
                return _encryptors.AddValue(factoryKey, encryptor);
            }

            return null;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _encryptors.Dispose();
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