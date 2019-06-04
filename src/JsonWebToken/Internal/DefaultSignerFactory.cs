// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken.Internal
{
    internal sealed class DefaultSignerFactory : SignerFactory
    {
        /// <summary>
        /// Creates a <see cref="Signer"/>.
        /// </summary>
        /// <param name="key">The key used for signature.</param>
        /// <param name="algorithm">The signature algorithm.</param>
        /// <returns></returns>
        public override Signer CreateForSignature(Jwk key, SignatureAlgorithm algorithm)
        {
            ThrowIfDisposed();

            if (key is null)
            {
                return NoneSigner.Default;
            }

            return key.CreateSignerForSignature(algorithm);
        }

        /// <summary>
        /// Creates a <see cref="Signer"/>.
        /// </summary>
        /// <param name="key">The key used for signature.</param>
        /// <param name="algorithm">The signature algorithm.</param>
        /// <returns></returns>
        public override Signer CreateForValidation(Jwk key, SignatureAlgorithm algorithm)
        {
            ThrowIfDisposed();

            if (key is null)
            {
                return NoneSigner.Default;
            }

            return key.CreateSignerForValidation(algorithm);
        }
    }
}