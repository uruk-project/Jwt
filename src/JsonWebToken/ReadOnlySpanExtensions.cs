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
    internal static class ReadOnlySpanExtensions
    {
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector256<T> AsVector256<T>(this ReadOnlySpan<byte> span) where T : struct
        {
            return MemoryMarshal.GetReference(span).AsVector256<T>();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref Vector256<T> AsVector256<T>(this ref byte span) where T : struct
        {
            return ref Unsafe.As<byte, Vector256<T>>(ref span);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector256<T> AsVector256<T>(this ReadOnlySpan<byte> span, IntPtr offset) where T : struct
        {
            return MemoryMarshal.GetReference(span).AsVector256<T>(offset);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref Vector256<T> AsVector256<T>(this ref byte span, IntPtr offset) where T : struct
        {
            return ref Unsafe.AddByteOffset(ref Unsafe.As<byte, Vector256<T>>(ref span), offset);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<T> AsVector128<T>(this ReadOnlySpan<byte> span) where T : struct
        {
            return MemoryMarshal.GetReference(span).AsVector128<T>();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref Vector128<T> AsVector128<T>(this ref byte span) where T : struct
        {
            return ref Unsafe.As<byte, Vector128<T>>(ref span);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<T> AsVector128<T>(this ReadOnlySpan<byte> span, IntPtr offset) where T : struct
        {
            return MemoryMarshal.GetReference(span).AsVector128<T>(offset);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref Vector128<T> AsVector128<T>(this ref byte span, IntPtr offset) where T : struct
        {
            return ref Unsafe.AddByteOffset(ref Unsafe.As<byte, Vector128<T>>(ref span), offset);
        }
#endif

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref T ReadUnaligned<T>(this ref byte span, IntPtr offset) where T : struct
        {
            return ref Unsafe.AddByteOffset(ref Unsafe.As<byte, T>(ref span), offset);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ref T ReadUnaligned<T>(this ref byte span) where T : struct
        {
            return ref Unsafe.As<byte, T>(ref span);
        }
    }
}
