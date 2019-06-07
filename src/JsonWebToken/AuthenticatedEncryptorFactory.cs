// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a factory of <see cref="AuthenticatedEncryptor"/>.
    /// </summary>
    public abstract class AuthenticatedEncryptorFactory : IDisposable
    {
        /// <summary>
        /// Gets the store of <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        protected HashSet<AuthenticatedEncryptor> Encryptors { get; } = new HashSet<AuthenticatedEncryptor>();

        /// <summary>
        /// Release managed resources.
        /// </summary>
        /// <param name="disposing"></param>
        protected abstract void Dispose(bool disposing);

        /// <summary>
        /// Release manged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        
        /// <summary>
        /// Creates an <see cref="AuthenticatedEncryptor"/>.
        /// </summary>
        /// <param name="key">The key used for encryption.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        public abstract AuthenticatedEncryptor Create(Jwk key, EncryptionAlgorithm encryptionAlgorithm);
    }
}