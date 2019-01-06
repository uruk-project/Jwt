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
        /// <param name="willCreateSignatures">Defines whether the <see cref="Signer"/> will be used for signature of for validation.</param>
        /// <returns></returns>
        public override Signer Create(Jwk key, SignatureAlgorithm algorithm, bool willCreateSignatures)
        {
            ThrowIfDisposed();

            if (algorithm is null)
            {
                return null;
            }

            var signers = willCreateSignatures ? VerificationSigners : CreationSigners;
            var factoryKey = new CryptographicFactoryKey(key, algorithm.Id);
            if (signers.TryGetValue(factoryKey, out var cachedSigner))
            {
                return cachedSigner;
            }

            if (key.IsSupported(algorithm))
            {
                var signer = key.CreateSigner(algorithm, willCreateSignatures);
                return signers.AddValue(factoryKey, signer);
            }

            return null;
        }
    }
}