// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if SUPPORT_SIMD
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
        /// <param name="prepend">Optionnal. The data to hash before the source. Must be of the length of <see cref="BlockSize"/> or less.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        /// <param name="workingSet">Optionnal. The working set used for computing the hash. Useful if you expect to chain hashing in the same thread and you want to avoid memory allocations. Use the method <see cref="GetWorkingSetSize(int)"/> for getting the required size. </param>
        public abstract void ComputeHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination, Span<byte> workingSet);

        /// <summary>
        /// Computes the required working set size.
        /// </summary>
        /// <param name="sourceLength"></param>
        /// <returns></returns>
        public abstract int GetWorkingSetSize(int sourceLength);

        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public abstract int HashSize { get; }

        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public abstract int BlockSize { get; }

#if SUPPORT_SIMD
        private static ReadOnlySpan<byte> LittleEndianUInt64 => new byte[32]
        {
            7, 6, 5, 4, 3, 2, 1, 0,
            15, 14, 13, 12, 11, 10, 9, 8,
            23, 22, 21, 20, 19, 18, 17, 16,
            31, 30, 29, 28, 27, 26, 25, 24
        };    
        
        private static ReadOnlySpan<byte> LittleEndianUInt32 => new byte[32]
        {
            3, 2, 1, 0, 7, 6, 5, 4,
            11, 10, 9, 8, 15, 14, 13, 12,
            19, 18, 17, 16, 23, 22, 21, 20,
            27, 26, 25, 24, 31, 30, 29, 28
        };

        /// <summary>
        /// The 128 bits shuffle mask for reverting endianness of 2 Int64.
        /// </summary>
        protected static readonly Vector128<byte> EndiannessMask128UInt64 = ReadVector128(LittleEndianUInt64);

        /// <summary>
        /// The 256 bits shuffle mask for reverting endianness of 4 Int64.
        /// </summary>
        protected static readonly Vector256<byte> EndiannessMask256UInt64 = ReadVector256(LittleEndianUInt64);

        /// <summary>
        /// The 128 bits shuffle mask for reverting endianness of 4 Int32.
        /// </summary>
        protected static readonly Vector128<byte> EndiannessMask128UInt32 = ReadVector128(LittleEndianUInt32);

        /// <summary>
        /// The 256 bits shuffle mask for reverting endianness of 8 Int32.
        /// </summary>
        protected static readonly Vector256<byte> EndianessnMask256UInt32 = ReadVector256(LittleEndianUInt32);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<byte> ReadVector256(ReadOnlySpan<byte> data)
        {
            ref byte tmp = ref MemoryMarshal.GetReference(data);
            return Unsafe.As<byte, Vector256<byte>>(ref tmp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> ReadVector128(ReadOnlySpan<byte> data)
        {
            ref byte tmp = ref MemoryMarshal.GetReference(data);
            return Unsafe.As<byte, Vector128<byte>>(ref tmp);
        }
#endif
    }
}
