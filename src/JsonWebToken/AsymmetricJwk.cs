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
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(byte[] d)
        {
            if (d == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.d);
            }

            D = d;
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

            D = Base64Url.Decode(d!); // ! => [DoesNotReturn]
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

            D = d;
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

            D = Base64Url.Decode(d!); // ! => [DoesNotReturn]
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

            D = d;
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

            D = Base64Url.Decode(d!); // ! => [DoesNotReturn]
        }

        /// <summary>
        /// Gets or sets the 'd' (ECC - Private Key OR RSA - Private Exponent).
        /// </summary>
        public byte[]? D { get; internal set; }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        public abstract bool HasPrivateKey { get; }

        /// <inheritsdoc />
        protected override AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            return AuthenticatedEncryptor.Empty;
        }
    }
}
