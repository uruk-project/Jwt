using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    public sealed class SignatureFactory : IDisposable
    {
        private readonly ConcurrentDictionary<ProviderFactoryKey, SignatureProvider> _providers = new ConcurrentDictionary<ProviderFactoryKey, SignatureProvider>(JwkEqualityComparer.Default);
        private readonly ConcurrentDictionary<ProviderFactoryKey, SignatureProvider> _validationProviders = new ConcurrentDictionary<ProviderFactoryKey, SignatureProvider>(JwkEqualityComparer.Default);

        public SignatureProvider Create(JsonWebKey key, SignatureAlgorithm algorithm, bool willCreateSignatures)
        {
            if (algorithm == null)
            {
                return null;
            }

            var providers = willCreateSignatures ? _validationProviders : _providers;
            var factoryKey = new ProviderFactoryKey(key, algorithm.Id);
            if (providers.TryGetValue(factoryKey, out var cachedProvider))
            {
                return cachedProvider;
            }

            if (key.IsSupportedAlgorithm(algorithm))
            {
                var provider = key.CreateSignatureProvider(algorithm, willCreateSignatures);
                if (!providers.TryAdd(factoryKey, provider) && providers.TryGetValue(factoryKey, out cachedProvider))
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