// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System.Collections.Generic;

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
        public PlaintextJweDescriptor(IDictionary<string, object> header, string payload)
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
            return EncryptToken(context, Payload);
        }
    }
}
