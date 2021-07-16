// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;

namespace JsonWebToken
{
    /// <summary>Defines an encrypted JWT with a <see cref="string"/> payload.</summary>
    public sealed class PlaintextJweDescriptor : JweDescriptor<string>
    {
        private string _payload;

        /// <summary>Initializes a new instance of <see cref="PlaintextJweDescriptor"/>.</summary>
        public PlaintextJweDescriptor(Jwk encryptionKey, KeyManagementAlgorithm alg, EncryptionAlgorithm enc, CompressionAlgorithm? zip = null, string? typ = JwtMediaTypeValues.Plain, string? cty = null)
            : base(encryptionKey, alg, enc, zip, typ, cty)
        {
            _payload = string.Empty;
        }


        /// <inheritdoc/>
        public override string Payload
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

        /// <inheritsdoc />
        public override void Encode(EncodingContext context)
        {
            int payloadLength = Utf8.GetMaxByteCount(_payload.Length);
            byte[]? payloadToReturnToPool = null;
            Span<byte> encodedPayload = payloadLength > Constants.MaxStackallocBytes
                             ? (payloadToReturnToPool = ArrayPool<byte>.Shared.Rent(payloadLength))
                             : stackalloc byte[payloadLength];

            try
            {
                int bytesWritten = Utf8.GetBytes(_payload, encodedPayload);
                EncryptToken(encodedPayload.Slice(0, bytesWritten), context);
            }
            finally
            {
                if (payloadToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(payloadToReturnToPool);
                }
            }
        }

        /// <inheritdoc/>
        public override void Validate()
        {
        }
    }
}
