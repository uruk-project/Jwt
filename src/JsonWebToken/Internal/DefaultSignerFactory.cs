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

            if (algorithm is null)
            {
                goto NotSupported;
            }

            var signers = CreationSigners;
            var factoryKey = new CryptographicFactoryKey(key, algorithm.Id);
            if (signers.TryGetValue(factoryKey, out var cachedSigner))
            {
                return cachedSigner;
            }

            if (key.IsSupported(algorithm))
            {
                var signer = key.CreateSignerForSignature(algorithm);
                return signers.AddValue(factoryKey, signer);
            }

        NotSupported:
            return null;
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

            if (algorithm is null)
            {
                goto NotSupported;
            }

            var signers = VerificationSigners;
            var factoryKey = new CryptographicFactoryKey(key, algorithm.Id);
            if (signers.TryGetValue(factoryKey, out var cachedSigner))
            {
                return cachedSigner;
            }

            if (key.IsSupported(algorithm))
            {
                var signer = key.CreateSignerForValidation(algorithm);
                return signers.AddValue(factoryKey, signer);
            }

        NotSupported:
            return null;
        }
    }
}