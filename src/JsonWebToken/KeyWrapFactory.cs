using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    public sealed class KeyWrapFactory : IDisposable
    {
        private readonly ConcurrentDictionary<ProviderFactoryKey, KeyWrapProvider> _providers = new ConcurrentDictionary<ProviderFactoryKey, KeyWrapProvider>(JwkEqualityComparer.Default);

        public KeyWrapProvider Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            if (encryptionAlgorithm == null || contentEncryptionAlgorithm == null)
            {
                return null;
            }

            var algorithmKey = (encryptionAlgorithm.Id << 8) | (byte)contentEncryptionAlgorithm.Id;
            var factoryKey = new ProviderFactoryKey(key, algorithmKey);
            if (_providers.TryGetValue(factoryKey, out var cachedProvider))
            {
                return cachedProvider;
            }

            if (key.IsSupportedAlgorithm(contentEncryptionAlgorithm))
            {
                var provider = key.CreateKeyWrapProvider(encryptionAlgorithm, contentEncryptionAlgorithm);
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