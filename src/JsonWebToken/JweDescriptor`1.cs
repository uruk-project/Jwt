// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <typeparamref name="TDescriptor"/> as payload.
    /// </summary>
    public class JweDescriptor<TDescriptor> : EncryptedJwtDescriptor<TDescriptor> where TDescriptor : JwsDescriptor, new()
    {
        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        public JweDescriptor()
            : base(new JwtObject(3), new TDescriptor())
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        /// <param name="payload"></param>
        public JweDescriptor(TDescriptor payload)
            : base(new JwtObject(3), payload)
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        public JweDescriptor(JwtObject header, TDescriptor payload)
            : base(header, payload)
        {
        }

        /// <inheritsdoc />
        public override void Encode(EncodingContext context)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            var ctx = new EncodingContext(bufferWriter, context.HeaderCache, context.TokenLifetimeInSeconds, context.GenerateIssuedTime);
            Payload?.Encode(ctx);
            EncryptToken(bufferWriter.WrittenSpan, context.BufferWriter);
        }

        /// <inheritsdoc />
        public override void Validate()
        {
            Payload?.Validate();
            base.Validate();
        }
    }

    /// <summary>
    /// Defines an encrypted JWT with a <typeparamref name="TDescriptor"/> as payload.
    /// </summary>
    public class JweDescriptorX<TDescriptor> : EncryptedJwtDescriptorX<TDescriptor> where TDescriptor : JwsDescriptorX, new()
    {
        private TDescriptor? _payload;

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
