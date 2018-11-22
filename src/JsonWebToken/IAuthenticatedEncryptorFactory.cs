// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a factory used to creates <see cref="AuthenticatedEncryptor"/>.
    /// </summary>
    public interface IAuthenticatedEncryptorFactory : IDisposable
    {
        /// <summary>
        /// Creates an <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        /// <param name="key">The key used for encryption.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        AuthenticatedEncryptor Create(Jwk key, EncryptionAlgorithm encryptionAlgorithm);
    }
}