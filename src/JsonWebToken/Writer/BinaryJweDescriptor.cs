// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a binary payload.
    /// </summary>
    public sealed class BinaryJweDescriptor : EncryptedJwtDescriptor<byte[]>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BinaryJweDescriptor"/> class.
        /// </summary>
        /// <param name="encryptionKey"></param>
        /// <param name="alg"></param>
        /// <param name="enc"></param>
        /// <param name="zip"></param>
        public BinaryJweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null)
            : base(encryptionKey, alg, enc, zip)
        {
        }

        /// <inheritdoc/>
        public override byte[]? Payload { get; set; }

        /// <inheritdoc />
        public override void Encode(EncodingContext context)
        {
            EncryptToken(Payload, context.BufferWriter);
        }
    }
}
