// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    public class DefaultAuthenticatedEncryptorFactory : IAuthenticatedEncryptorFactory
    {
        private readonly CryptographicStore<AuthenticatedEncryptor> _encryptors = new CryptographicStore<AuthenticatedEncryptor>();

        private bool _disposed;

        /// <summary>
        /// Creates an <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        /// <param name="key">The key used for encryption.</param>
        /// <param name="encryptionAlgorithm">then encryption algorithm/</param>
        public virtual AuthenticatedEncryptor Create(JsonWebKey key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var factoryKey = new CryptographicFactoryKey(key, encryptionAlgorithm.Id);
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

        void IDisposable.Dispose()
        {
            Dispose();
        }
    }
}