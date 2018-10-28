// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    public class DefaultSignerFactory : ISignerFactory
    {
        private readonly CryptographicStore<Signer> _signers = new CryptographicStore<Signer>();
        private readonly CryptographicStore<Signer> _validationSigners = new CryptographicStore<Signer>();
        private bool _disposed;

        /// <summary>
        /// Creates a <see cref="Signer"/>.
        /// </summary>
        /// <param name="key">The key used for signature.</param>
        /// <param name="algorithm">The signature algorithm.</param>
        /// <param name="willCreateSignatures">Defines whether the <see cref="Signer"/> will be used for signature of for validation.</param>
        /// <returns></returns>
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