// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) using the SHA2-256 hash function.
    /// </summary>
    public class HmacSha256 : HmacSha2
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HmacSha256"/> class.
        /// </summary>
        /// <param name="key"></param>
        public HmacSha256(ReadOnlySpan<byte> key)
            : base(Sha256.Shared, key)
        {
        }
    }
}
