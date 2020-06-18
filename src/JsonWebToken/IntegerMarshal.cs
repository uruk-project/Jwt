// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace JsonWebToken
{
    internal static class IntegerMarshal
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong ReadUInt64(ReadOnlySpan<byte> value)
            => ReadUInt64(ref MemoryMarshal.GetReference(value));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong ReadUInt64(ref byte value)
            => Unsafe.ReadUnaligned<ulong>(ref value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong ReadUInt64(ReadOnlySpan<byte> value, int elementOffset)
            => ReadUInt64(ref MemoryMarshal.GetReference(value), elementOffset);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong ReadUInt64(ref byte value, int elementOffset)
            => Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref value, elementOffset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong ReadUInt56(ReadOnlySpan<byte> value)
            => ReadUInt56(ref MemoryMarshal.GetReference(value));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong ReadUInt56(ref byte value)
            => Unsafe.ReadUnaligned<ulong>(ref value) & 0x00ffffffffffffff;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong ReadUInt56(ref byte value, int elementOffset)
            => Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref value, elementOffset)) & 0x00ffffffffffffff;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ReadUInt32(ReadOnlySpan<byte> value)
            => ReadUInt32(ref MemoryMarshal.GetReference(value));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ReadUInt32(ref byte value)
            => Unsafe.ReadUnaligned<uint>(ref value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ReadUInt32(ReadOnlySpan<byte> value, int elementOffset)
            => ReadUInt32(ref MemoryMarshal.GetReference(value), elementOffset);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ReadUInt32(ref byte value, int elementOffset)
            => Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref value, elementOffset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ReadUInt24(ReadOnlySpan<byte> value)
            => ReadUInt24(ref MemoryMarshal.GetReference(value));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ReadUInt24(ref byte value)
            => Unsafe.ReadUnaligned<uint>(ref value) & 0x00ffffff;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint ReadUInt16(ReadOnlySpan<byte> value)
            => ReadUInt16(ref MemoryMarshal.GetReference(value));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ushort ReadUInt16(ref byte value)
            => Unsafe.ReadUnaligned<ushort>(ref value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ushort ReadUInt16(ReadOnlySpan<byte> value, int elementOffset)
            => ReadUInt16(ref MemoryMarshal.GetReference(value), elementOffset);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ushort ReadUInt16(ref byte value, int elementOffset)
            => Unsafe.ReadUnaligned<ushort>(ref Unsafe.Add(ref value, elementOffset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte ReadUInt8(ReadOnlySpan<byte> value)
            => MemoryMarshal.GetReference(value);
    }
}
