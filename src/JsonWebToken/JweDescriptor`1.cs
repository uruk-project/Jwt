// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Buffers;

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
            : base(new JwtObject(), new TDescriptor())
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JweDescriptor"/>.
        /// </summary>
        /// <param name="payload"></param>
        public JweDescriptor(TDescriptor payload)
            : base(new JwtObject(), payload)
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
        public override void Encode(EncodingContext context, IBufferWriter<byte> output)
        {
            using (var bufferWriter = new ArrayBufferWriter())
            {
                Payload?.Encode(context, bufferWriter);
                EncryptToken(context, bufferWriter.WrittenSpan, output);
            }
        }

        /// <inheritsdoc />
        public override void Validate()
        {
            Payload?.Validate();
            base.Validate();
        }
    }
}
