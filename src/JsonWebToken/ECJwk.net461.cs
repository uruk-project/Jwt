// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NET461
using System;
using System.Buffers;
using System.Text.Json;

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
        public override ReadOnlySpan<byte> Kty => throw new NotImplementedException();

        /// <inheritsdoc />
        public override int KeySizeInBits => throw new NotImplementedException();

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> AsSpan() => throw new NotImplementedException();

        /// <inheritsdoc />
        public override bool Equals(Jwk? other) => throw new NotImplementedException();

        /// <inheritsdoc />
        public override bool SupportSignature(SignatureAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        public override bool SupportKeyManagement(KeyManagementAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        public override bool SupportEncryption(EncryptionAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override void Canonicalize(IBufferWriter<byte> bufferWriter) => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override Signer CreateSigner(SignatureAlgorithm algorithm) => throw new NotImplementedException();
    }
}
#endif
