// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWT with a binary payload.</summary>
    public sealed class BinaryJweDescriptor : JweDescriptor<byte[]>
    {
        private byte[] _payload;

        /// <summary>Initializes a new instance of the <see cref="BinaryJweDescriptor"/> class.</summary>
        public BinaryJweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = JwtMediaTypeValues.OctetStream, string? cty = null)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
            _payload = Array.Empty<byte>();
        }

        /// <inheritdoc/>
        public override byte[] Payload
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


        /// <inheritdoc />
        public override void Encode(EncodingContext context)
        {
            EncryptToken(_payload, context);
        }

        /// <inheritdoc />
        public override void Validate()
        {
        }
    }
}
