// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWK contained within a JWT.</summary>
    public sealed class JwkJweDescriptor : JweDescriptor<Jwk>
    {
        private Jwk _payload;

        /// <summary>Initializes a new instance of the <see cref="JwkJweDescriptor"/> class.</summary>
        public JwkJweDescriptor(SymmetricJwk encryptionKey, SymmetricKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwk)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
            _payload = Jwk.None;
        }
        
        /// <summary>Initializes a new instance of the <see cref="JwkJweDescriptor"/> class.</summary>
        public JwkJweDescriptor(PasswordBasedJwk encryptionKey, PasswordBasedKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwk)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
            _payload = Jwk.None;
        }

        /// <summary>Initializes a new instance of the <see cref="JwkJweDescriptor"/> class.</summary>
        public JwkJweDescriptor(RsaJwk encryptionKey, RsaKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwk)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
            _payload = Jwk.None;
        }

        /// <summary>Initializes a new instance of the <see cref="JwkJweDescriptor"/> class.</summary>
        public JwkJweDescriptor(ECJwk encryptionKey, ECKeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwk)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
            _payload = Jwk.None;
        }

        /// <inheritdoc/>
        public override Jwk Payload
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
            writer.Flush();
            EncryptToken(bufferWriter.WrittenSpan, context);
        }

        /// <inheritdoc/>
        public override void Validate()
        {
            _payload.Validate();
        }
    }
}
