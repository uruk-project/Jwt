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
        /// <param name="prepend">The data to hash before the source. Optionnal. Must be of the length of <see cref="BlockSize"/>.</param>
        /// <param name="w">The working set. Optionnal.</param>
        public abstract void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend, Span<uint> w);

        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        /// <param name="prepend">The data to hash before the source. Optionnal. Must be of the length of <see cref="BlockSize"/>.</param>
        /// <param name="w">The working set. Optionnal.</param>
        public abstract void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend, Span<ulong> w);

        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public abstract int HashSize { get; }

        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public abstract int BlockSize { get; }
    }
}
