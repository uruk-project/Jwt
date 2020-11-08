// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <typeparamref name="TDescriptor"/> as payload.
    /// </summary>
    public class JweDescriptor<TDescriptor> : EncryptedJwtDescriptor<TDescriptor> where TDescriptor : JwsDescriptor, new()
    {
        private TDescriptor? _payload;

        /// <summary>
        /// Initializes a new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        public JweDescriptor()
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        public JweDescriptor(TDescriptor payload)
        {
            _payload = payload;
        }

        /// <inheritdoc/>
        public override TDescriptor Payload
        {
            get => _payload ??= new TDescriptor();
            set => _payload = value;
        }

        /// <inheritsdoc />
        public override void Encode(EncodingContext context)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            var ctx = new EncodingContext(bufferWriter, context.HeaderCache, context.TokenLifetimeInSeconds, context.GenerateIssuedTime);
            Payload.Encode(ctx);
            EncryptToken(bufferWriter.WrittenSpan, context.BufferWriter);
        }

        /// <inheritsdoc />
        public override void Validate()
        {
            Payload.Validate();
            base.Validate();
        }
    }
}
