using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>
    /// Extensions methods for <see cref="Sha2"/>.
    /// </summary>
    public static class Sha2Extensions
    {
        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="sha2">The SHA-2 algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this Sha2 sha2, ReadOnlySpan<byte> source, Span<byte> destination)
            => sha2.ComputeHash(source, destination, default);
    }
}
