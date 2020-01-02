// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

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
            : base(new Sha384(), key)
        {
        }

        /// <inheritsdoc />
        public override int BlockSize => 128;

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            // hash(o_key_pad ∥ hash(i_key_pad ∥ message));
            Span<ulong> w = stackalloc ulong[80];
            Sha2.ComputeHash(source, destination, _innerPadKey.Span, w);
            Sha2.ComputeHash(destination, destination, _outerPadKey.Span, w);
        }

        /// <inheritsdoc />
        protected override void ComputeKeyHash(ReadOnlySpan<byte> key, Span<byte> keyPrime)
        {
            Sha2.ComputeHash(key, keyPrime, default, default(Span<ulong>));
        }
    }
}
