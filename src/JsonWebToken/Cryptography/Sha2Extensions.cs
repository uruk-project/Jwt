// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

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
        /// <param name="sha256">The SHA-2 algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this Sha256 sha256, ReadOnlySpan<byte> source, Span<byte> destination)
        {
            sha256.ComputeHash(source, destination, default, default(Span<uint>));
        }

        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="sha384">The SHA-2 algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this Sha384 sha384, ReadOnlySpan<byte> source, Span<byte> destination)
        {
            sha384.ComputeHash(source, destination, default, default(Span<ulong>));
        }

        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="sha512">The SHA-2 algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this Sha512 sha512, ReadOnlySpan<byte> source, Span<byte> destination)
        {
            sha512.ComputeHash(source, destination, default, default(Span<ulong>));
        }

        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="sha2">The SHA-2 algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        /// <param name="W">The working set. Optionnal.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this Sha2 sha2, ReadOnlySpan<byte> source, Span<byte> destination, Span<uint> W)
            => sha2.ComputeHash(source, destination, default, W);

        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="sha2">The SHA-2 algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        /// <param name="W">The working set. Optionnal.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this Sha2 sha2, ReadOnlySpan<byte> source, Span<byte> destination, Span<ulong> W)
            => sha2.ComputeHash(source, destination, default, W);
    }
}
