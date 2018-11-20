// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Defines an encrypted JWT with a binary payload.
    /// </summary>
    public sealed class BinaryJweDescriptor : EncryptedJwtDescriptor<byte[]>
    {
        public BinaryJweDescriptor(byte[] payload)
            : base(payload)
        {
        }

        public BinaryJweDescriptor(IDictionary<string, object> header, byte[] payload)
            : base(header, payload)
        {
        }

        /// <inheritdoc />
        public override string Encode(EncodingContext context)
        {
            return EncryptToken(context, Payload);
        }
    }
}
