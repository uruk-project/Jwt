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
        /// The 'd' (ECC - Private Key OR RSA - Private Exponent).
        /// </summary>
        protected internal byte[]? _d;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(byte[] d)
        {
            if (d == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _d = d;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(string d)
        {
            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _d = Base64Url.Decode(d);
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
        protected AsymmetricJwk(byte[] d, SignatureAlgorithm alg)
            : base(alg)
        {
            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _d = d;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(string d, SignatureAlgorithm alg)
            : base(alg)
        {
            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _d = Base64Url.Decode(d);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(KeyManagementAlgorithm alg)
            : base(alg)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(byte[] d, KeyManagementAlgorithm alg)
            : base(alg)
        {
            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _d = d;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(string d, KeyManagementAlgorithm alg)
            : base(alg)
        {
            if (d is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            _d = Base64Url.Decode(d);
        }

        /// <summary>
        /// Gets the 'd' (ECC - Private Key OR RSA - Private Exponent).
        /// </summary>
        public ReadOnlySpan<byte> D => _d;

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        public bool HasPrivateKey => !(_d is null);

        /// <inheritsdoc />
        public override void Dispose()
        {
            base.Dispose();
            if (_d != null)
            {
                CryptographicOperations.ZeroMemory(_d);
            }
        }
    }
}
