// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Collections.Generic;

namespace JsonWebToken.Internal
{
    internal sealed class DefaultKeyWrapperFactory : KeyWrapperFactory
    {
        private readonly HashSet<KeyWrapper> _keyWrappers = new HashSet<KeyWrapper>();
        private bool _disposed;

        /// <summary>
        /// Creates a <see cref="KeyWrapper"/>.
        /// </summary>
        /// <param name="key">the key used for key wrapping.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <param name="contentEncryptionAlgorithm">The content encryption algorithm.</param>
        public override KeyWrapper Create(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            ThrowIfDisposed();

            if (key is null)
            {
                return null;
            }

            return key.CreateKeyWrapper(encryptionAlgorithm, contentEncryptionAlgorithm);
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    foreach (var item in _keyWrappers)
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