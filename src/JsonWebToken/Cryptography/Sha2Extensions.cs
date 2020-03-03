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
        /// <param name="sha2">The SHA-2 algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this Sha2 sha2, ReadOnlySpan<byte> source, Span<byte> destination)
        {
            sha2.ComputeHash(source, destination, default, default);
        }

        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="sha2">The SHA-2 algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="prepend">The data to concatenated to <paramref name="source"/> before to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this Sha2 sha2, ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination)
        {
            sha2.ComputeHash(source, destination, prepend, default);
        }

        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="sha2">The SHA-2 algorithm.</param>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        /// <param name="workingSet">The working set. Optionnal.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ComputeHash(this Sha2 sha2, ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> workingSet)
            => sha2.ComputeHash(source, destination, default, workingSet);
    }
}
