// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Represents an asymmetric JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public abstract class AsymmetricJwk : Jwk
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk()
        {
        }

        /// <summary>
        /// Gets or sets the 'd' (ECC - Private Key OR RSA - Private Exponent).
        /// </summary>
        public byte[] D { get; set; }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        public abstract bool HasPrivateKey { get; }

        /// <inheritsdoc />
        public override AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm algorithm)
        {
            return null;
        }
    }
}
