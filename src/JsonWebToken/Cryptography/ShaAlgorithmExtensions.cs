using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>
    /// Extensions methods for <see cref="ShaAlgorithm"/>.
    /// </summary>
    public static class ShaAlgorithmExtensions
    {
        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="sha">The SHA algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this ShaAlgorithm sha, ReadOnlySpan<byte> source, Span<byte> destination)
            => sha.ComputeHash(source, destination, default);
    }
}
