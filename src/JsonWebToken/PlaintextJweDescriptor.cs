// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

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
        public override byte[] Encode(EncodingContext context)
        {
            int payloadLength = Payload.Length;
            byte[] payloadToReturnToPool = null;
            Span<byte> encodedPayload = payloadLength > Constants.MaxStackallocBytes
                             ? (payloadToReturnToPool = ArrayPool<byte>.Shared.Rent(payloadLength)).AsSpan(0, payloadLength)
                             : stackalloc byte[payloadLength];

            try
            {
#if !NETSTANDARD2_0
                Encoding.UTF8.GetBytes(Payload, encodedPayload);
#else
                EncodingHelper.GetUtf8Bytes(Payload.AsSpan(), encodedPayload);
#endif
                return EncryptToken(context, encodedPayload);
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
