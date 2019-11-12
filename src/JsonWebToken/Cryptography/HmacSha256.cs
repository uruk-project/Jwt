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
    /// Computes a Hash-based Message Authentication Code (HMAC) using the SHA2-256 hash function.
    /// </summary>
    public class HmacSha256 : HmacSha
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HmacSha256"/> class.
        /// </summary>
        /// <param name="key"></param>
        public HmacSha256(ReadOnlySpan<byte> key)
            : base(new Sha256(), key)
        {
        }

        /// <inheritsdoc />
        public override int BlockSize => 64;
    }
}
