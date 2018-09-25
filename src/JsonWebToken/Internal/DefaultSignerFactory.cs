using System;
using System.Collections.Concurrent;

namespace JsonWebToken
{
    public class DefaultSignerFactory : ISignerFactory
    {
        private readonly ConcurrentDictionary<ProviderFactoryKey, Signer> _signers = new ConcurrentDictionary<ProviderFactoryKey, Signer>(JwkEqualityComparer.Default);
        private readonly ConcurrentDictionary<ProviderFactoryKey, Signer> _validationSigners = new ConcurrentDictionary<ProviderFactoryKey, Signer>(JwkEqualityComparer.Default);
        private bool _disposed;

        public virtual Signer Create(JsonWebKey key, SignatureAlgorithm algorithm, bool willCreateSignatures)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            if (algorithm == null)
            {
                return null;
            }

            var signers = willCreateSignatures ? _validationSigners : _signers;
            var factoryKey = new ProviderFactoryKey(key, algorithm.Id);
            if (signers.TryGetValue(factoryKey, out var cachedSigner))
            {
                return cachedSigner;
            }

            if (key.IsSupported(algorithm))
            {
                var signer = key.CreateSigner(algorithm, willCreateSignatures);
                if (!signers.TryAdd(factoryKey, signer) && signers.TryGetValue(factoryKey, out cachedSigner))
                {
                    signer.Dispose();
                    return cachedSigner;
                }
                else
                {
                    return signer;
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
                    foreach (var signer in _signers)
                    {
                        signer.Value.Dispose();
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