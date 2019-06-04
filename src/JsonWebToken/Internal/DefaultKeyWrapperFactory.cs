// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken.Internal
{
    internal sealed class DefaultKeyWrapperFactory : KeyWrapperFactory
    {
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
    }
}