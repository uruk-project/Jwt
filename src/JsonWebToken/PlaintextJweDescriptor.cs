﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Text;
using JsonWebToken.Internal;

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
        /// <param name="header"></param>
        /// <param name="payload"></param>
        public PlaintextJweDescriptor(JwtObject header, string payload)
            : base(header, payload)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="PlaintextJweDescriptor"/>.
        /// </summary>
        /// <param name="payload"></param>
        public PlaintextJweDescriptor(string payload)
            : base(payload)
        {
        }
    
        /// <inheritsdoc />
        public override void Encode(EncodingContext context, IBufferWriter<byte> output)
        {
            int payloadLength = Payload.Length;
            byte[]? payloadToReturnToPool = null;
            Span<byte> encodedPayload = payloadLength > Constants.MaxStackallocBytes
                             ? (payloadToReturnToPool = ArrayPool<byte>.Shared.Rent(payloadLength)).AsSpan(0, payloadLength)
                             : stackalloc byte[payloadLength];

            try
            {
                Encoding.UTF8.GetBytes(Payload, encodedPayload);
                EncryptToken(context, encodedPayload, output);
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
