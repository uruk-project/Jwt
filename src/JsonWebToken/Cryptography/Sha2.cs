// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
using System.Runtime.Intrinsics;
#endif

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
        /// <param name="prepend">The data to hash before the source. Optionnal. Must be of the length of <see cref="BlockSize"/> or less.</param>
        /// <param name="w">The working set. Optionnal.</param>
        public abstract void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend, Span<uint> w);

        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        /// <param name="prepend">The data to hash before the source. Optionnal. Must be of the length of <see cref="BlockSize"/> or less.</param>
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

#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
        protected static ReadOnlySpan<byte> LittleEndianMask => new byte[32]
        {
            3, 2, 1, 0, 7, 6, 5, 4,
            11, 10, 9, 8, 15, 14, 13, 12,
            19, 18, 17, 16, 23, 22, 21, 20,
            27, 26, 25, 24, 31, 30, 29, 28
        };

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static Vector256<byte> ReadVector256(ReadOnlySpan<byte> data)
        {
            ref byte tmp = ref MemoryMarshal.GetReference(data);
            return Unsafe.As<byte, Vector256<byte>>(ref tmp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static Vector128<byte> ReadVector128(ReadOnlySpan<byte> data)
        {
            ref byte tmp = ref MemoryMarshal.GetReference(data);
            return Unsafe.As<byte, Vector128<byte>>(ref tmp);
        }
#endif
    }
}
