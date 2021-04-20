// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken.Cryptography
{
    internal static class CryptographicOperations
    {
        public static void ZeroMemory(Span<byte> buffer)
        {
            buffer.Clear();
        }

        // Optimized FixedTimeEquals
        public unsafe static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            int length = left.Length;
            if (length != right.Length)
            {
                return false;
            }

            fixed (byte* l = left)
            fixed (byte* r = right)
            {
                int accumulator;
                // fast-path for SHA256 (32 bytes & 16 for half),
                // SHA512 (64 bytes & 32 bytes for half) &
                // SHA384 (48 bytes & 24 bytes for half)
                accumulator = length switch
                {
                    16 => *(int*)l ^ *(int*)r
                        | *(int*)(l + sizeof(int)) ^ *(int*)(r + sizeof(int))
                        | *(int*)(l + 2 * sizeof(int)) ^ *(int*)(r + 2 * sizeof(int))
                        | *(int*)(l + 3 * sizeof(int)) ^ *(int*)(r + 3 * sizeof(int)),
                    32 => *(int*)l ^ *(int*)r
                        | *(int*)(l + sizeof(int)) ^ *(int*)(r + sizeof(int))
                        | *(int*)(l + 2 * sizeof(int)) ^ *(int*)(r + 2 * sizeof(int))
                        | *(int*)(l + 3 * sizeof(int)) ^ *(int*)(r + 3 * sizeof(int))
                        | *(int*)(l + 4 * sizeof(int)) ^ *(int*)(r + 4 * sizeof(int))
                        | *(int*)(l + 5 * sizeof(int)) ^ *(int*)(r + 5 * sizeof(int))
                        | *(int*)(l + 6 * sizeof(int)) ^ *(int*)(r + 6 * sizeof(int))
                        | *(int*)(l + 7 * sizeof(int)) ^ *(int*)(r + 7 * sizeof(int)),
                    64 => *(int*)l ^ *(int*)r
                        | *(int*)(l + sizeof(int)) ^ *(int*)(r + sizeof(int))
                        | *(int*)(l + 2 * sizeof(int)) ^ *(int*)(r + 2 * sizeof(int))
                        | *(int*)(l + 3 * sizeof(int)) ^ *(int*)(r + 3 * sizeof(int))
                        | *(int*)(l + 4 * sizeof(int)) ^ *(int*)(r + 4 * sizeof(int))
                        | *(int*)(l + 5 * sizeof(int)) ^ *(int*)(r + 5 * sizeof(int))
                        | *(int*)(l + 6 * sizeof(int)) ^ *(int*)(r + 6 * sizeof(int))
                        | *(int*)(l + 7 * sizeof(int)) ^ *(int*)(r + 7 * sizeof(int))
                        | *(int*)(l + 8 * sizeof(int)) ^ *(int*)(r + 8 * sizeof(int))
                        | *(int*)(l + 9 * sizeof(int)) ^ *(int*)(r + 9 * sizeof(int))
                        | *(int*)(l + 10 * sizeof(int)) ^ *(int*)(r + 10 * sizeof(int))
                        | *(int*)(l + 11 * sizeof(int)) ^ *(int*)(r + 11 * sizeof(int))
                        | *(int*)(l + 12 * sizeof(int)) ^ *(int*)(r + 12 * sizeof(int))
                        | *(int*)(l + 13 * sizeof(int)) ^ *(int*)(r + 13 * sizeof(int))
                        | *(int*)(l + 14 * sizeof(int)) ^ *(int*)(r + 14 * sizeof(int))
                        | *(int*)(l + 15 * sizeof(int)) ^ *(int*)(r + 15 * sizeof(int)),
                    24 => *(int*)l ^ *(int*)r
                        | *(int*)(l + sizeof(int)) ^ *(int*)(r + sizeof(int))
                        | *(int*)(l + 2 * sizeof(int)) ^ *(int*)(r + 2 * sizeof(int))
                        | *(int*)(l + 3 * sizeof(int)) ^ *(int*)(r + 3 * sizeof(int))
                        | *(int*)(l + 4 * sizeof(int)) ^ *(int*)(r + 4 * sizeof(int))
                        | *(int*)(l + 5 * sizeof(int)) ^ *(int*)(r + 5 * sizeof(int)),
                    48 => *(int*)l ^ *(int*)r
                        | *(int*)(l + sizeof(int)) ^ *(int*)(r + sizeof(int))
                        | *(int*)(l + 2 * sizeof(int)) ^ *(int*)(r + 2 * sizeof(int))
                        | *(int*)(l + 3 * sizeof(int)) ^ *(int*)(r + 3 * sizeof(int))
                        | *(int*)(l + 4 * sizeof(int)) ^ *(int*)(r + 4 * sizeof(int))
                        | *(int*)(l + 5 * sizeof(int)) ^ *(int*)(r + 5 * sizeof(int))
                        | *(int*)(l + 6 * sizeof(int)) ^ *(int*)(r + 6 * sizeof(int))
                        | *(int*)(l + 7 * sizeof(int)) ^ *(int*)(r + 7 * sizeof(int))
                        | *(int*)(l + 8 * sizeof(int)) ^ *(int*)(r + 8 * sizeof(int))
                        | *(int*)(l + 9 * sizeof(int)) ^ *(int*)(r + 9 * sizeof(int))
                        | *(int*)(l + 10 * sizeof(int)) ^ *(int*)(r + 10 * sizeof(int))
                        | *(int*)(l + 11 * sizeof(int)) ^ *(int*)(r + 11 * sizeof(int)),
                    0 => 0,
                    _ => Aggregate(l, r, length),
                };

                return accumulator == 0;
            }

            // NoOptimization because we want this method to be exactly as non-short-circuiting as written.
            // NoInlining because the NoOptimization would get lost if the method got inlined.
            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static int Aggregate(byte* l, byte* r, int length)
            {
                int offset = 0;
                int accumulator = 0;
                int end = length - sizeof(int);
                while ((int)(byte*)offset < end)
                {
                    accumulator |= *(int*)(l + offset) ^ *(int*)(r + offset);
                    offset += sizeof(int);
                }

                return accumulator | *(int*)(l + end) ^ *(int*)(r + end);
            }
        }
    }
}