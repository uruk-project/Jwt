using System;
#if NETCOREAPP3_0
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Represnets the base class for SHA algorithms.
    /// </summary>
    public abstract class ShaAlgorithm
    {
        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        /// <param name="prepend">The data to hash before the source. Optionnal.</param>
        public abstract void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend = default);

        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public abstract int HashSize { get; }
    }
}
