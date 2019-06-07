// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Collections.Generic;

namespace JsonWebToken.Internal
{
    internal sealed class DefaultSignerFactory : SignerFactory
    {
        private bool _disposed;

        private readonly HashSet<Signer> _signers = new HashSet<Signer>();

        /// <summary>
        /// Creates a <see cref="Signer"/>.
        /// </summary>
        /// <param name="key">The key used for signature.</param>
        /// <param name="algorithm">The signature algorithm.</param>
        /// <returns></returns>
        public override Signer Create(Jwk key, SignatureAlgorithm algorithm)
        {
            ThrowIfDisposed();

            if (key is null)
            {
                return NoneSigner.Default;
            }

            return key.CreateSigner(algorithm);
        }

        /// <summary>
        /// Releases the managed resources.
        /// </summary>
        /// <param name="disposing"></param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    foreach (var item in _signers)
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