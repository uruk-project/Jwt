using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    public sealed class AuthenticatedEncryptionFactory : IDisposable
    {
        private readonly ConcurrentDictionary<ProviderFactoryKey, AuthenticatedEncryptionProvider> _providers = new ConcurrentDictionary<ProviderFactoryKey, AuthenticatedEncryptionProvider>(JwkEqualityComparer.Default);

        public AuthenticatedEncryptionProvider Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm)
        {
            var factoryKey = new ProviderFactoryKey(key, encryptionAlgorithm.Id);
            if (_providers.TryGetValue(factoryKey, out var cachedProvider))
            {
                return cachedProvider;
            }

            if (key.IsSupportedAlgorithm(encryptionAlgorithm))
            {
                var provider = key.CreateAuthenticatedEncryptionProvider(encryptionAlgorithm);

                if (!_providers.TryAdd(factoryKey, provider) && _providers.TryGetValue(factoryKey, out cachedProvider))
                {
                    provider.Dispose();
                    return cachedProvider;
                }
                else
                {
                    return provider;
                }
            }

            return null;
        }

        public void Dispose()
        {
            foreach (var item in _providers)
            {
                item.Value.Dispose();
            }
        }
    }
}