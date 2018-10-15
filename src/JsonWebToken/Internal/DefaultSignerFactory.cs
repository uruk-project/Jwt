using System;

namespace JsonWebToken.Internal
{
    public class DefaultSignerFactory : ISignerFactory
    {
        private readonly CryptographicStore<Signer> _signers = new CryptographicStore<Signer>();
        private readonly CryptographicStore<Signer> _validationSigners = new CryptographicStore<Signer>();
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
            var factoryKey = new CryptographicFactoryKey(key, algorithm.Id);
            if (signers.TryGetValue(factoryKey, out var cachedSigner))
            {
                return cachedSigner;
            }

            if (key.IsSupported(algorithm))
            {
                var signer = key.CreateSigner(algorithm, willCreateSignatures);
                return signers.AddValue(factoryKey, signer);
            }

            return null;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _signers.Dispose();
                    _validationSigners.Dispose();
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