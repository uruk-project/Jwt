// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWK contains witin a JWT.</summary>
    public sealed class JwkJweDescriptor : JweDescriptor<Jwk>
    {
        /// <summary>Initializes a new instance of the <see cref="JwkJweDescriptor"/> class.</summary>
        public JwkJweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwk)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }

        /// <inheritdoc/>
        public override Jwk? Payload { get; set; }

        /// <inheritdoc/>
        public override void Encode(EncodingContext context)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            var ctx = new EncodingContext(bufferWriter, context);
            if (Payload is null)
            {
                ThrowHelper.ThrowInvalidOperationException_UndefinedPayload();
            }

            using var writer = new Utf8JsonWriter(ctx.BufferWriter);
            Payload.WriteTo(writer);
            writer.Flush();
            EncryptToken(bufferWriter.WrittenSpan, context);
        }
    }

    /// <summary>Defines an encrypted JWK contains witin a JWT.</summary>
    public sealed class JwksJweDescriptor : JweDescriptor<Jwks>
    {
        /// <summary>Initializes a new instance of the <see cref="JwkJweDescriptor"/> class.</summary>
        public JwksJweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwks)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }

        /// <inheritdoc/>
        public override Jwks? Payload { get; set; }

        /// <inheritdoc/>
        public override void Encode(EncodingContext context)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            var ctx = new EncodingContext(bufferWriter, context);
            if (Payload is null)
            {
                ThrowHelper.ThrowInvalidOperationException_UndefinedPayload();
            }

            using var writer = new Utf8JsonWriter(ctx.BufferWriter);
            Payload.WriteTo(writer);
            EncryptToken(bufferWriter.WrittenSpan, context);
        }
    }
}
