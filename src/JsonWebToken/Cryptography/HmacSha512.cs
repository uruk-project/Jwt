using System;
#if NETCOREAPP3_0
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) using the SHA2-512 hash function.
    /// </summary>
    public class HmacSha512 : HmacSha
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HmacSha512"/> class.
        /// </summary>
        /// <param name="key"></param>
        public HmacSha512(ReadOnlySpan<byte> key)
            : base(new Sha512(), key)
        {
        }

        /// <inheritsdoc />
        public override int BlockSize => 128;
    }
}
