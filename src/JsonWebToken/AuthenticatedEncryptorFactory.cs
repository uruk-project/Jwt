// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    public abstract class AuthenticatedEncryptorFactory : IDisposable
    {
        private bool _disposed;

        protected CryptographicStore<AuthenticatedEncryptor> Encryptors { get; } = new CryptographicStore<AuthenticatedEncryptor>();

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    Encryptors.Dispose();
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }
        }

        /// <summary>
        /// Creates an <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        /// <param name="key">The key used for encryption.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        public abstract AuthenticatedEncryptor Create(Jwk key, EncryptionAlgorithm encryptionAlgorithm);
    }
}