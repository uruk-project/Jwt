// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a <see cref="string"/> payload.
    /// </summary>
    public sealed class PlaintextJweDescriptor : EncryptedJwtDescriptor<string>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="PlaintextJweDescriptor"/>.
        /// </summary>
        /// <param name="payload"></param>
        public PlaintextJweDescriptor(string payload)
        {
            Payload = payload;
        }

        /// <inheritsdoc />
        public override string Payload { get; set; }

        /// <inheritsdoc />
        public override void Encode(EncodingContext context)
        {
            int payloadLength = Utf8.GetMaxByteCount(Payload.Length);
            byte[]? payloadToReturnToPool = null;
            Span<byte> encodedPayload = payloadLength > Constants.MaxStackallocBytes
                             ? (payloadToReturnToPool = ArrayPool<byte>.Shared.Rent(payloadLength))
                             : stackalloc byte[payloadLength];

            try
            {
                int bytesWritten = Utf8.GetBytes(Payload, encodedPayload);
                EncryptToken(encodedPayload.Slice(0, bytesWritten), context.BufferWriter);
            }
            finally
            {
                if (payloadToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(payloadToReturnToPool);
                }
            }
        }
    }
}
