using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    public sealed class AuthenticatedEncryptorFactory : IDisposable
    {
        private readonly ConcurrentDictionary<ProviderFactoryKey, AuthenticatedEncryptor> _encryptors = new ConcurrentDictionary<ProviderFactoryKey, AuthenticatedEncryptor>(JwkEqualityComparer.Default);

        public AuthenticatedEncryptor Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm)
        {
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

        public void Dispose()
        {
            foreach (var encryptor in _encryptors)
            {
                encryptor.Value.Dispose();
            }
        }
    }
}