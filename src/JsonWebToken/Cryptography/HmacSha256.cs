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
            : base(new Sha256(), key)
        {
        }

        /// <inheritsdoc />
        public override int BlockSize => 64;

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            // hash(o_key_pad ∥ hash(i_key_pad ∥ message));         
            Span<uint> W = stackalloc uint[64];
            Sha2.ComputeHash(source, destination, _innerPadKey.Span, W);
            Sha2.ComputeHash(destination, destination, _outerPadKey.Span, W);
        }

        /// <inheritsdoc />
        protected override void ComputeKeyHash(ReadOnlySpan<byte> key, Span<byte> keyPrime)
        {
            Sha2.ComputeHash(key, keyPrime, default, default(Span<uint>));
        }
    }
}
