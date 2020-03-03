// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) using the SHA2-384 hash function.
    /// </summary>
    public class HmacSha384 : HmacSha2
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HmacSha384"/> class.
        /// </summary>
        /// <param name="key"></param>
        public HmacSha384(ReadOnlySpan<byte> key)
            : base(Sha384.Shared, key)
        {
        }
    }
}
