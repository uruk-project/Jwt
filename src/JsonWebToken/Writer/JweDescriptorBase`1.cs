// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <typeparamref name="TDescriptor"/> as payload.
    /// </summary>
    public abstract class JweDescriptorBase<TDescriptor> : JweDescriptor<TDescriptor> where TDescriptor : JwsDescriptor
    {
        private TDescriptor? _payload;

        /// <summary>
        /// Initializes a new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        public JweDescriptorBase(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = null)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }

        /// <inheritdoc/>
        public override TDescriptor? Payload
        {
            get => _payload;
            set => _payload = value;
        }

        /// <inheritsdoc />
        public override void Encode(EncodingContext context)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            var ctx = new EncodingContext(bufferWriter, context);
            if (!(_payload is null))
            {
                _payload.Encode(ctx);
                EncryptToken(bufferWriter.WrittenSpan, context.BufferWriter);
            }
            else
            {
                ThrowHelper.ThrowInvalidOperationException_UndefinedPayload();
            }
        }

        /// <inheritsdoc />
        public override void Validate()
        {
            base.Validate();
            if (!(_payload is null))
            {
                _payload.Validate();
            }
        }
    }
}
