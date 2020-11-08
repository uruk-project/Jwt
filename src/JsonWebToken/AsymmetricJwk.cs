// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

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
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(SignatureAlgorithm alg)
            : base(alg)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(KeyManagementAlgorithm alg)
            : base(alg)
        {
        }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        public abstract bool HasPrivateKey { get; }
    }
}
