// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken.Internal
{
    internal class DefaultAuthenticatedEncryptorFactory : AuthenticatedEncryptorFactory
    {
        /// <summary>
        /// Creates an <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        /// <param name="key">The key used for encryption.</param>
        /// <param name="encryptionAlgorithm">then encryption algorithm/</param>
        public override AuthenticatedEncryptor Create(Jwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            ThrowIfDisposed();

            var factoryKey = new CryptographicFactoryKey(key, encryptionAlgorithm.Id);
            if (Encryptors.TryGetValue(factoryKey, out var cachedEncryptor))
            {
                return cachedEncryptor;
            }

            if (key.IsSupported(encryptionAlgorithm))
            {
                var encryptor = key.CreateAuthenticatedEncryptor(encryptionAlgorithm);
                return Encryptors.AddValue(factoryKey, encryptor);
            }

            return null;
        }
    }
}