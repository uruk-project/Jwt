// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) using the SHA2-512 hash function.
    /// </summary>
    public class HmacSha512 : HmacSha2
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HmacSha512"/> class.
        /// </summary>
        /// <param name="key"></param>
        public HmacSha512(ReadOnlySpan<byte> key)
            : base(Sha512.Shared, key)
        {
        }
    }
}
