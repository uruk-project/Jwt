// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Collections.Concurrent;

namespace JsonWebToken
{
    /// <summary>
    /// Represents an asymmetric JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public abstract class AsymmetricJwk : Jwk
    {
        // Lazy?
        private readonly ConcurrentDictionary<int, Signer> _creationSigners = new ConcurrentDictionary<int, Signer>();
        private readonly ConcurrentDictionary<int, Signer> _verificationSigners = new ConcurrentDictionary<int, Signer>();

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
                Errors.ThrowArgumentNullException(ExceptionArgument.d);
            }

            D = d;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricJwk"/> class.
        /// </summary>
        protected AsymmetricJwk(string d)
        {
            if (d == null)
            {
                Errors.ThrowArgumentNullException(ExceptionArgument.d);
            }

            D = Base64Url.Decode(d);
        }
        /// <summary>
        /// Gets or sets the 'd' (ECC - Private Key OR RSA - Private Exponent).
        /// </summary>
        public byte[] D { get; internal set; }

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

        /// <inheritsdoc />
        public override Signer CreateSignerForSignature(SignatureAlgorithm algorithm)
        {
            return CreateSigner(algorithm, _creationSigners, willCreateSignatures: true);
        }

        /// <inheritsdoc />
        public override Signer CreateSignerForValidation(SignatureAlgorithm algorithm)
        {
            return CreateSigner(algorithm, _verificationSigners, willCreateSignatures: false);
        }

        /// <summary>
        /// Creates a <see cref="Signer"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        /// <param name="signers"></param>
        /// <param name="willCreateSignatures"></param>
        protected Signer CreateSigner(SignatureAlgorithm algorithm, ConcurrentDictionary<int, Signer> signers, bool willCreateSignatures)
        {
            if (algorithm is null)
            {
                return null;
            }

            if (signers.TryGetValue(algorithm.Id, out var cachedSigner))
            {
                return cachedSigner;
            }

            if (IsSupported(algorithm))
            {
                var signer = CreateNewSigner(algorithm, willCreateSignatures);
                signers.TryAdd(algorithm.Id, signer);
                return signer;
            }

            return null;
        }

        /// <summary>
        /// Creates a fresh new <see cref="Signer"/> with the current <see cref="Jwk"/> as key.
        /// </summary>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/> used for the signatures.</param>
        /// <param name="willCreateSignatures"></param>
        protected abstract Signer CreateNewSigner(SignatureAlgorithm algorithm, bool willCreateSignatures);

        /// <inheritsdoc />
        protected override AuthenticatedEncryptor CreateNewAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            return null;
        }
    }
}
