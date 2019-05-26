// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represent a factory of <see cref="Signer"/>.
    /// </summary>
    public abstract class SignerFactory : IDisposable
    {
        private bool _disposed;

        /// <summary>
        /// Gets the store of <see cref="Signer"/> used for signature creation.
        /// </summary>
        public CryptographicStore<Signer> CreationSigners { get; } = new CryptographicStore<Signer>();

        /// <summary>
        /// Gets the store of <see cref="Signer"/> used for signature verification.
        /// </summary>
        public CryptographicStore<Signer> VerificationSigners { get; } = new CryptographicStore<Signer>();

        /// <summary>
        /// Releases the managed resources.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    CreationSigners.Dispose();
                    VerificationSigners.Dispose();
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Releases the managed resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// Throws if the current object were previously disposed.
        /// </summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }
        }

        /// <summary>
        /// Creates a <see cref="Signer"/>.
        /// </summary>
        /// <param name="key">The key used for signature.</param>
        /// <param name="algorithm">The signature algorithm.</param>
        /// <returns></returns>
        public abstract Signer CreateForValidation(Jwk key, SignatureAlgorithm algorithm);

        /// <summary>
        /// Creates a <see cref="Signer"/>.
        /// </summary>
        /// <param name="key">The key used for signature.</param>
        /// <param name="algorithm">The signature algorithm.</param>
        /// <returns></returns>
        public abstract Signer CreateForSignature(Jwk key, SignatureAlgorithm algorithm);
    }
}