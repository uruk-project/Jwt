// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Collections.Generic;

namespace JsonWebToken.Internal
{
    internal sealed class DefaultAuthenticatedEncryptorFactory : AuthenticatedEncryptorFactory
    {
        private readonly HashSet<AuthenticatedEncryptor> _encryptors = new HashSet<AuthenticatedEncryptor>();
        private bool _disposed;

        /// <summary>
        /// Creates an <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        /// <param name="key">The key used for encryption.</param>
        /// <param name="encryptionAlgorithm">then encryption algorithm/</param>
        public override AuthenticatedEncryptor Create(Jwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            ThrowIfDisposed();

            if (key is null)
            {
                return null;
            }

            return key.CreateAuthenticatedEncryptor(encryptionAlgorithm);
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    foreach (var item in _encryptors)
                    {
                        item.Key.Release(item);
                        item.Dispose();
                    }
                }

                _disposed = true;
            }
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }
        }
    }
}