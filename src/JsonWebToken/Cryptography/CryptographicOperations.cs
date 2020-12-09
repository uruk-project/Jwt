// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if SUPPORT_SIMD
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken.Cryptography
{
    internal static class CryptographicOperations
    {
        public static void ZeroMemory(Span<byte> buffer)
        {
            buffer.Clear();
        }

        // Optimized byte-based FixedTimeEquals. Inspired from https://github.com/dotnet/corefx/blob/master/src/Common/src/CoreLib/System/SpanHelpers.Byte.cs
        public unsafe static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            int length = left.Length;
            if (length != right.Length)
            {
                return false;
            }

            bool result;
#if SUPPORT_SIMD
            if (Avx2.IsSupported && length >= sizeof(Vector256<byte>))
            {
                ref byte first = ref MemoryMarshal.GetReference(left);
                ref byte second = ref MemoryMarshal.GetReference(right);
                int accumulator = unchecked((int)0b1111_1111_1111_1111_1111_1111_1111_1111);
                IntPtr offset = (IntPtr)0;
                int end = length - sizeof(Vector256<byte>);
                while ((int)(byte*)offset < end)
                {
                    accumulator &= Avx2.MoveMask(Avx2.CompareEqual(first.AsVector256<byte>(offset), second.AsVector256<byte>(offset)));
                    offset += sizeof(Vector256<byte>);
                }

                accumulator &= Avx2.MoveMask(Avx2.CompareEqual(first.AsVector256<byte>((IntPtr)end), second.AsVector256<byte>((IntPtr)end)));
                result = accumulator == unchecked((int)0b1111_1111_1111_1111_1111_1111_1111_1111);
            }
            else if (Sse2.IsSupported && length >= sizeof(Vector128<byte>))
            {
                ref byte first = ref MemoryMarshal.GetReference(left);
                ref byte second = ref MemoryMarshal.GetReference(right);
                int accumulator = 0b1111_1111_1111_1111;
                IntPtr offset = (IntPtr)0;
                int end = length - sizeof(Vector128<byte>);
                while ((int)(byte*)offset < end)
                {
                    accumulator &= Sse2.MoveMask(Sse2.CompareEqual(first.AsVector128<byte>(offset), second.AsVector128<byte>(offset)));
                    offset += sizeof(Vector128<byte>);
                }

                accumulator &= Sse2.MoveMask(Sse2.CompareEqual(first.AsVector128<byte>((IntPtr)end), second.AsVector128<byte>((IntPtr)end)));
                result = accumulator == 0b1111_1111_1111_1111;
            }
            else
#endif
            if (length >= sizeof(ulong))
            {
                ref byte first = ref MemoryMarshal.GetReference(left);
                ref byte second = ref MemoryMarshal.GetReference(right);
                ulong accumulator = 0L;
                IntPtr offset = (IntPtr)0;
                int end = length - sizeof(ulong);

                while ((int)(byte*)offset < end)
                {
                    accumulator |= first.ReadUnaligned<ulong>(offset) ^ second.ReadUnaligned<ulong>(offset);
                    offset += sizeof(ulong);
                }

                accumulator |= first.ReadUnaligned<ulong>((IntPtr)end) ^ second.ReadUnaligned<ulong>((IntPtr)end);
                result = accumulator == 0L;
            }
            else if (length != 0)
            {
                int accumulator = 0;
                IntPtr offset = (IntPtr)0;
                ref byte first = ref MemoryMarshal.GetReference(left);
                ref byte second = ref MemoryMarshal.GetReference(right);
                while ((int)(byte*)offset < length)
                {
                    accumulator |= Unsafe.AddByteOffset(ref first, offset) - Unsafe.AddByteOffset(ref second, offset);
                    offset += 1;
                }

                result = accumulator == 0;
            }
            else
            {
                result = true;
            }

            return result;
        }
    }
}