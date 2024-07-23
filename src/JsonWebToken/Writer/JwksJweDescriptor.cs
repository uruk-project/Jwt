// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWKS contained within a JWT.</summary>
    public sealed class JwksJweDescriptor : JweDescriptor<Jwks>
    {
        private Jwks _payload;

        /// <summary>Initializes a new instance of the <see cref="JwksJweDescriptor"/> class.</summary>
        public JwksJweDescriptor(SymmetricJwk encryptionKey, SymmetricKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwks)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
            _payload = new Jwks();
        }

        /// <summary>Initializes a new instance of the <see cref="JwksJweDescriptor"/> class.</summary>
        public JwksJweDescriptor(RsaJwk encryptionKey, RsaKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwks)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
            _payload = new Jwks();
        }

        /// <summary>Initializes a new instance of the <see cref="JwksJweDescriptor"/> class.</summary>
        public JwksJweDescriptor(ECJwk encryptionKey, ECKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwks)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
            _payload = new Jwks();
        }

        /// <inheritdoc/>
        public override Jwks Payload
        {
            get => _payload;
            set
            {
                if (value is null)
                {
                    ThrowHelper.ThrowArgumentNullException(ExceptionArgument.value);
                }

                _payload = value;
            }
        }

        /// <inheritdoc/>
        public override void Encode(EncodingContext context)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            var ctx = new EncodingContext(bufferWriter, context);
            using var writer = new Utf8JsonWriter(ctx.BufferWriter);
            _payload.WriteTo(writer);
            EncryptToken(bufferWriter.WrittenSpan, context);
        }

        /// <inheritdoc/>
        public override void Validate()
        {
            _payload.Validate();
        }
    }
}
