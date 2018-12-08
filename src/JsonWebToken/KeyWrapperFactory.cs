// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a factory of <see cref="KeyWrapper"/>.
    /// </summary>
    public abstract class KeyWrapperFactory : IDisposable
    {
        private bool _disposed;

        /// <summary>
        /// Gets the store of <see cref="KeyWrapper"/> used for key wrapping. 
        /// </summary>
        protected CryptographicStore<KeyWrapper> KeyWrappers { get; } = new CryptographicStore<KeyWrapper>();

        /// <summary>
        /// Dispose the managed resources.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    KeyWrappers.Dispose();
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Dispose the managed resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// Throw if the current <see cref="KeyWrapperFactory"/> is already disposed.
        /// </summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }
        }

        /// <summary>
        /// Creates a <see cref="KeyWrapper"/>.
        /// </summary>
        /// <param name="key">The key used for key wrapping.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <param name="contentEncryptionAlgorithm">The content encryption algorithm.</param>
        public abstract KeyWrapper Create(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm);
    }
}