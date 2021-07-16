// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWT with a <typeparamref name="TDescriptor"/> as payload.</summary>
    public abstract partial class JweDescriptorBase<TDescriptor> : JweDescriptor<TDescriptor> where TDescriptor : JwsDescriptor
    {
        /// <summary>Initializes a new instance of <see cref="JweDescriptor"/>.</summary>
        public JweDescriptorBase(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = null, string? cty = JwtContentTypeValues.Jwt)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
        }

        /// <inheritsdoc />
        public override void Encode(EncodingContext context)
        {
            using var bufferWriter = new PooledByteBufferWriter();
            var ctx = new EncodingContext(bufferWriter, context);
            Payload.Encode(ctx);
            EncryptToken(bufferWriter.WrittenSpan, context);
        }
    }
}
