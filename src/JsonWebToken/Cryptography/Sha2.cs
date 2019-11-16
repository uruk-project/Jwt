using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the base class for SHA-2 algorithms.
    /// </summary>
    public abstract class Sha2
    {
        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        /// <param name="prepend">The data to hash before the source. Optionnal.</param>
        public abstract void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend);
        
        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public abstract int HashSize { get; }
    }
}
