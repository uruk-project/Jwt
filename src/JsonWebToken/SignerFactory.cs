// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    public abstract class SignerFactory : IDisposable
    {
        private bool _disposed;

        public CryptographicStore<Signer> Signers { get; } = new CryptographicStore<Signer>();

        public CryptographicStore<Signer> ValidationSigners { get; } = new CryptographicStore<Signer>();

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    Signers.Dispose();
                    ValidationSigners.Dispose();
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
        /// Creates a <see cref="Signer"/>.
        /// </summary>
        /// <param name="key">The key used for signature.</param>
        /// <param name="algorithm">The signature algorithm.</param>
        /// <param name="willCreateSignatures"><c>true</c> if the <see cref="Signer"/> is used for creating signatures. <c>false</c> if the <see cref="Signer"/> is used for validating signatures.</param>
        /// <returns></returns>
        public abstract Signer Create(Jwk key, SignatureAlgorithm algorithm, bool willCreateSignatures);
    }
}