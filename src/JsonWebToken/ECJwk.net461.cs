// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if !SUPPORT_ELLIPTIC_CURVE
using System;
using System.Buffers;
using System.Text.Json;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Represents an Elliptic Curve JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class ECJwk : AsymmetricJwk
    {
        /// <inheritsdoc />
        public override bool HasPrivateKey => throw new NotImplementedException();

        /// <inheritsdoc />
        public override JsonEncodedText Kty => throw new NotImplementedException();

        /// <inheritsdoc />
        public override int KeySizeInBits => throw new NotImplementedException();

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> AsSpan() => throw new NotImplementedException();

        /// <inheritsdoc />

        /// <inheritsdoc />
        public override bool SupportSignature(SignatureAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        public override bool SupportKeyManagement(KeyManagementAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        public override bool SupportEncryption(EncryptionAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritdoc />
        protected internal override void Canonicalize(Span<byte> buffer) => throw new NotImplementedException();

        /// <inheritdoc />
        protected internal override int GetCanonicalizeSize() => throw new NotImplementedException();  

        /// <inheritsdoc />
        protected override KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override Signer CreateSigner(SignatureAlgorithm algorithm) => throw new NotImplementedException();    
 
        /// <inheritsdoc />
        protected override SignatureVerifier CreateSignatureVerifier(SignatureAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        public override Jwk AsPublicKey() => throw new NotImplementedException();
    }
}
#endif
