// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a factory of <see cref="AuthenticatedEncryptor"/>.
    /// </summary>
    public abstract class AuthenticatedEncryptorFactory : IDisposable
    {
        private bool _disposed;

        /// <summary>
        /// Gets the store of <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        protected CryptographicStore<AuthenticatedEncryptor> Encryptors { get; } = new CryptographicStore<AuthenticatedEncryptor>();

        /// <summary>
        /// Release managed resources.
        /// </summary>
        /// <param name="disposing"></param>
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

        /// <summary>
        /// Release manged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// Thow an <see cref="ObjectDisposedException"/> if this object is already disposed.
        /// </summary>
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