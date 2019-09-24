// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
        public override bool IsSupported(SignatureAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        public override bool IsSupported(KeyManagementAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        public override bool IsSupported(EncryptionAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override void Canonicalize(IBufferWriter<byte> bufferWriter) => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm) => throw new NotImplementedException();

        /// <inheritsdoc />
        protected override Signer CreateSigner(SignatureAlgorithm algorithm) => throw new NotImplementedException();
    }
}
#endif
