// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if NETCOREAPP3_0
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken
{
    // Based on https://github.com/gfoidl/Base64
    // Scalar based on https://github.com/dotnet/corefx/tree/ec34e99b876ea1119f37986ead894f4eded1a19a/src/System.Memory/src/System/Buffers/Text
    // SSE2   based on https://github.com/aklomp/base64/tree/a27c565d1b6c676beaf297fe503c4518185666f7/lib/arch/ssse3
    // AVX2   based on https://github.com/aklomp/base64/tree/a27c565d1b6c676beaf297fe503c4518185666f7/lib/arch/avx2
    internal sealed class Base64UrlEncoder
    {
        public int GetMaxDecodedLength(int encodedLength)
        {
            if ((uint)encodedLength >= int.MaxValue)
            {
                goto InvalidData;
            }

            int numPaddingChars = GetNumBase64PaddingCharsToAddForDecode(encodedLength);

            if (numPaddingChars == 3)
            {
                goto InvalidData;
            }

            int base64Len = encodedLength + numPaddingChars;
            if (base64Len < 0)    // overflow
            {
                goto InvalidData;
            }

            Debug.Assert(base64Len % 4 == 0, "Invariant: Array length must be a multiple of 4.");

            return ((base64Len >> 2) * 3) - numPaddingChars;

        InvalidData:
            ThrowHelper.ThrowFormatException_MalformdedInput(encodedLength);
            return 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool TryGetDataLength(int urlEncodedLen, out int base64Len, out int dataLength)
        {
            int numPaddingChars = GetNumBase64PaddingCharsToAddForDecode(urlEncodedLen);

            if (numPaddingChars == 3)
            {
                goto InvalidData;
            }

            base64Len = urlEncodedLen + numPaddingChars;
            if (base64Len < 0)    // overflow
            {
                goto InvalidData;
            }

            Debug.Assert(base64Len % 4 == 0, "Invariant: Array length must be a multiple of 4.");

            dataLength = ((base64Len >> 2) * 3) - numPaddingChars;
            return true;

        InvalidData:
            base64Len = 0;
            dataLength = 0;
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GetNumBase64PaddingCharsToAddForDecode(int encodedLength)
        {
            // Calculation is:
            // switch (inputLength % 4)
            // 0 -> 0
            // 2 -> 2
            // 3 -> 1
            // default -> format exception
            return (4 - encodedLength) & 3;
        }

        public OperationStatus TryDecode(ReadOnlySpan<byte> encoded, Span<byte> data, out int consumed, out int written)
        {
            if (encoded.IsEmpty)
            {
                consumed = 0;
                written = 0;
                return OperationStatus.Done;
            }

            ref byte src = ref MemoryMarshal.GetReference(encoded);
            int srcLength = encoded.Length;

            return TryDecode(ref src, srcLength, data, out consumed, out written);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private OperationStatus TryDecode(ref byte src, int inputLength, Span<byte> data, out int consumed, out int written)
        {
            const int skipLastChunk = 4;
            uint sourceIndex = 0;
            uint destIndex = 0;

            if (!TryGetDataLength(inputLength, out int base64Len, out int decodedLength))
            {
                goto InvalidDataExit;
            }

            int srcLength = base64Len & ~0x3;       // only decode input up to the closest multiple of 4.
            int maxSrcLength = srcLength;
            int destLength = data.Length;

            // max. 2 padding chars
            if (destLength < decodedLength - 2)
            {
                // For overflow see comment below
                maxSrcLength = (int)FastDiv3(destLength) * 4;
            }

            ref byte destBytes = ref MemoryMarshal.GetReference(data);

#if NETCOREAPP3_0
            if (Ssse3.IsSupported && maxSrcLength >= 24)
            {
                if (Avx2.IsSupported && maxSrcLength >= 45)
                {
                    Avx2Decode(ref src, ref destBytes, maxSrcLength, ref sourceIndex, ref destIndex);

                    if (sourceIndex == srcLength)
                        goto DoneExit;
                }

                if (Ssse3.IsSupported && (maxSrcLength >= (int)sourceIndex + 24))
                {
                    Ssse3Decode(ref src, ref destBytes, maxSrcLength, ref sourceIndex, ref destIndex);

                    if (sourceIndex == srcLength)
                        goto DoneExit;
                }
            }
#endif

            if (destLength >= decodedLength)
            {
                maxSrcLength = srcLength - skipLastChunk;
            }
            else
            {
                maxSrcLength = (int)FastDiv3(destLength) * 4;
            }

            ref sbyte decodingMap = ref MemoryMarshal.GetReference(DecodingMap);

            // In order to elide the movsxd in the loop
            if (sourceIndex < maxSrcLength)
            {
                do
                {
                    int result = DecodeFour(ref Unsafe.Add(ref src, (IntPtr)sourceIndex), ref decodingMap);

                    if (result < 0)
                        goto InvalidDataExit;

                    WriteThreeLowOrderBytes(ref destBytes, destIndex, result);
                    destIndex += 3;
                    sourceIndex += 4;
                }
                while (sourceIndex < (uint)maxSrcLength);
            }

            if (maxSrcLength != srcLength - skipLastChunk)
                goto DestinationTooSmallExit;

            // If input is less than 4 bytes, srcLength == sourceIndex == 0
            // If input is not a multiple of 4, sourceIndex == srcLength != 0
            if (sourceIndex == srcLength)
            {
                goto InvalidDataExit;
            }

            // Handle last four bytes. There are 0, 1, 2 padding chars.
            int numPaddingChars = base64Len - inputLength;
            ref byte lastFourStart = ref Unsafe.Add(ref src, srcLength - 4);

            if (numPaddingChars == 0)
            {
                int result = DecodeFour(ref lastFourStart, ref decodingMap);

                if (result < 0) goto InvalidDataExit;
                if (destIndex > destLength - 3) goto DestinationTooSmallExit;

                WriteThreeLowOrderBytes(ref destBytes, destIndex, result);
                sourceIndex += 4;
                destIndex += 3;
            }
            else if (numPaddingChars == 1)
            {
                int result = DecodeThree(ref lastFourStart, ref decodingMap);

                if (result < 0)
                    goto InvalidDataExit;

                if (destIndex > destLength - 2)
                    goto DestinationTooSmallExit;

                WriteTwoLowOrderBytes(ref destBytes, destIndex, result);
                sourceIndex += 3;
                destIndex += 2;
            }
            else
            {
                int result = DecodeTwo(ref lastFourStart, ref decodingMap);

                if (result < 0)
                    goto InvalidDataExit;

                if (destIndex > destLength - 1)
                    goto DestinationTooSmallExit;

                WriteOneLowOrderByte(ref destBytes, destIndex, result);
                sourceIndex += 2;
                destIndex += 1;
            }

            if (srcLength != base64Len)
                goto InvalidDataExit;
#if NETCOREAPP3_0
            DoneExit:
#endif
            consumed = (int)sourceIndex;
            written = (int)destIndex;
            return OperationStatus.Done;

        DestinationTooSmallExit:
            if (srcLength != inputLength)
                goto InvalidDataExit; // if input is not a multiple of 4, and there is no more data, return invalid data instead

            consumed = (int)sourceIndex;
            written = (int)destIndex;
            return OperationStatus.DestinationTooSmall;

        InvalidDataExit:
            consumed = (int)sourceIndex;
            written = (int)destIndex;
            return OperationStatus.InvalidData;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int DecodeFour(ref byte encoded, ref sbyte decodingMap)
        {
            uint t0 = Unsafe.Add(ref encoded, 0);
            uint t1 = Unsafe.Add(ref encoded, 1);
            uint t2 = Unsafe.Add(ref encoded, 2);
            uint t3 = Unsafe.Add(ref encoded, 3);

            int i0 = Unsafe.Add(ref decodingMap, (IntPtr)t0);
            int i1 = Unsafe.Add(ref decodingMap, (IntPtr)t1);
            int i2 = Unsafe.Add(ref decodingMap, (IntPtr)t2);
            int i3 = Unsafe.Add(ref decodingMap, (IntPtr)t3);

            i0 <<= 18;
            i1 <<= 12;
            i2 <<= 6;

            i0 |= i3;
            i1 |= i2;

            i0 |= i1;
            return i0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void WriteThreeLowOrderBytes(ref byte destination, uint destIndex, int value)
        {
            Unsafe.Add(ref destination, (IntPtr)(destIndex + 0)) = (byte)(value >> 16);
            Unsafe.Add(ref destination, (IntPtr)(destIndex + 1)) = (byte)(value >> 8);
            Unsafe.Add(ref destination, (IntPtr)(destIndex + 2)) = (byte)value;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int DecodeThree(ref byte encoded, ref sbyte decodingMap)
        {
            uint t0 = encoded;
            uint t1 = Unsafe.Add(ref encoded, 1);
            uint t2 = Unsafe.Add(ref encoded, 2);

            int i0 = Unsafe.Add(ref decodingMap, (IntPtr)t0);
            int i1 = Unsafe.Add(ref decodingMap, (IntPtr)t1);
            int i2 = Unsafe.Add(ref decodingMap, (IntPtr)t2);

            return i0 << 18 | i1 << 12 | i2 << 6;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int DecodeTwo(ref byte encoded, ref sbyte decodingMap)
        {
            uint t0 = encoded;
            uint t1 = Unsafe.Add(ref encoded, 1);

            int i0 = Unsafe.Add(ref decodingMap, (IntPtr)t0);
            int i1 = Unsafe.Add(ref decodingMap, (IntPtr)t1);

            return i0 << 18 | i1 << 12;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void WriteTwoLowOrderBytes(ref byte destination, uint destIndex, int value)
        {
            Unsafe.Add(ref destination, (IntPtr)destIndex) = (byte)(value >> 16);
            Unsafe.Add(ref destination, (IntPtr)(destIndex + 1)) = (byte)(value >> 8);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void WriteOneLowOrderByte(ref byte destination, uint destIndex, int value)
        {
            Unsafe.Add(ref destination, (IntPtr)destIndex) = (byte)(value >> 16);
        }

        private static ReadOnlySpan<sbyte> DecodingMap
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                ReadOnlySpan<sbyte> map = new sbyte[256 + 1] {
                    0,      // https://github.com/dotnet/coreclr/issues/23194
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
                    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
                    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
                    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
                    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
                };

                // Slicing is necessary to "unlink" the ref and let the JIT keep it in a register
                return map.Slice(1);
            }
        }

#if NETCOREAPP3_0
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Avx2Decode(ref byte src, ref byte dest, int sourceLength, ref uint sourceIndex, ref uint destIndex)
        {
            ref byte srcStart = ref src;
            ref byte destStart = ref dest;
            ref byte simdSrcEnd = ref Unsafe.Add(ref src, (IntPtr)((uint)sourceLength - 45 + 1));    //  +1 for <=

            // The JIT won't hoist these "constants", so help it
            Vector256<sbyte> allOnes = Vector256.Create((sbyte)-1);                // -1 = 0xFF = true in simd
            Vector256<sbyte> lutHi = ReadVector256(AvxDecodeLutHi);
            Vector256<sbyte> lutLo = ReadVector256(AvxDecodeLutLo);
            Vector256<sbyte> lutShift = ReadVector256(AvxDecodeLutShift);
            Vector256<sbyte> mask5F = Vector256.Create((sbyte)0x5F);              // ASCII: _
            Vector256<sbyte> shift5F = Vector256.Create((sbyte)33);                // high nibble is 0x5 -> range 'P' .. 'Z' for shift, not '+' (0x2)
            Vector256<sbyte> shuffleConstant0 = Vector256.Create(0x01400140).AsSByte();
            Vector256<short> shuffleConstant1 = Vector256.Create(0x00011000).AsInt16();
            Vector256<sbyte> shuffleVec = ReadVector256(AvxDecodeShuffleVec);
            Vector256<int> permuteVec = ReadVector256(AvxDecodePermuteVec).AsInt32();

            do
            {
                Vector256<sbyte> str = ReadVector256(ref src);

                Vector256<sbyte> hiNibbles = Avx2.And(Avx2.ShiftRightLogical(str.AsInt32(), 4).AsSByte(), mask5F);
                Vector256<sbyte> lowerBound = Avx2.Shuffle(lutLo, hiNibbles);
                Vector256<sbyte> upperBound = Avx2.Shuffle(lutHi, hiNibbles);

                Vector256<sbyte> below = LessThan(str, lowerBound, allOnes);
                Vector256<sbyte> above = Avx2.CompareGreaterThan(str, upperBound);
                Vector256<sbyte> eq5F = Avx2.CompareEqual(str, mask5F);
                Vector256<sbyte> outside = Avx2.AndNot(eq5F, Avx2.Or(below, above));

                // https://github.com/dotnet/coreclr/issues/21247
                if (Avx2.MoveMask(outside) != 0)
                    break;

                Vector256<sbyte> shift = Avx2.Shuffle(lutShift, hiNibbles);
                str = Avx2.Add(str, shift);
                str = Avx2.Add(str, Avx2.And(eq5F, shift5F));

                Vector256<short> merge_ab_and_bc = Avx2.MultiplyAddAdjacent(str.AsByte(), shuffleConstant0);
                Vector256<int> @out = Avx2.MultiplyAddAdjacent(merge_ab_and_bc, shuffleConstant1);
                @out = Avx2.Shuffle(@out.AsSByte(), shuffleVec).AsInt32();
                str = Avx2.PermuteVar8x32(@out, permuteVec).AsSByte();

                WriteVector256(ref dest, str);

                src = ref Unsafe.Add(ref src, 32);
                dest = ref Unsafe.Add(ref dest, 24);
            }
            while (Unsafe.IsAddressLessThan(ref src, ref simdSrcEnd));

            // Cast to ulong to avoid the overflow-check. Codegen for x86 is still good.
            sourceIndex = (uint)(ulong)Unsafe.ByteOffset(ref srcStart, ref src);
            destIndex = (uint)(ulong)Unsafe.ByteOffset(ref destStart, ref dest);
        }

        private static ReadOnlySpan<sbyte> AvxDecodeLutLo => new sbyte[32]
        {
            lInv, lInv, 0x2D, 0x30,
            0x41, 0x50, 0x61, 0x70,
            lInv, lInv, lInv, lInv,
            lInv, lInv, lInv, lInv,
            lInv, lInv, 0x2D, 0x30,
            0x41, 0x50, 0x61, 0x70,
            lInv, lInv, lInv, lInv,
            lInv, lInv, lInv, lInv
        };

        private static ReadOnlySpan<sbyte> AvxDecodeLutHi => new sbyte[32]
        {
            hInv, hInv, 0x2D, 0x39,
            0x4F, 0x5A, 0x6F, 0x7A,
            hInv, hInv, hInv, hInv,
            hInv, hInv, hInv, hInv,
            hInv, hInv, 0x2D, 0x39,
            0x4F, 0x5A, 0x6F, 0x7A,
            hInv, hInv, hInv, hInv,
            hInv, hInv, hInv, hInv
        };

        private static ReadOnlySpan<sbyte> AvxDecodeLutShift => new sbyte[32]
        {
            0,   0,  17,   4,
            -65, -65, -71, -71,
            0,   0,   0,   0,
            0,   0,   0,   0,
            0,   0,  17,   4,
            -65, -65, -71, -71,
            0,   0,   0,   0,
            0,   0,   0,   0
        };

        private static ReadOnlySpan<sbyte> AvxDecodeShuffleVec => new sbyte[32]
        {
            2,  1,  0,  6,
            5,  4, 10,  9,
            8, 14, 13, 12,
            -1, -1, -1, -1,
            2,  1,  0,  6,
            5,  4, 10,  9,
            8, 14, 13, 12,
            -1, -1, -1, -1
        };

        // Originally this is of type int, but ROSpan<byte>for static data can handly (s)byte only
        // due to endianess concerns.
        private static ReadOnlySpan<sbyte> AvxDecodePermuteVec => new sbyte[32]
        {
            0,  0,  0,  0,
            1,  0,  0,  0,
            2,  0,  0,  0,
            4,  0,  0,  0,
            5,  0,  0,  0,
            6,  0,  0,  0,
            -1, -1, -1, -1,
            -1, -1, -1, -1
        };

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Ssse3Decode(ref byte src, ref byte dest, int sourceLength, ref uint sourceIndex, ref uint destIndex)
        {
            ref byte srcStart = ref src;
            ref byte destStart = ref dest;
            ref byte simdSrcEnd = ref Unsafe.Add(ref src, (IntPtr)((uint)sourceLength - 24 + 1));    //  +1 for <=

            // Shift to workspace
            src = ref Unsafe.Add(ref src, (IntPtr)sourceIndex);
            dest = ref Unsafe.Add(ref dest, (IntPtr)destIndex);

            // The JIT won't hoist these "constants", so help it
            Vector128<sbyte> lutHi = ReadVector128(SseDecodeLutHi);
            Vector128<sbyte> lutLo = ReadVector128(SseDecodeLutLo);
            Vector128<sbyte> lutShift = ReadVector128(SseDecodeLutShift);
            Vector128<sbyte> mask5F = Vector128.Create((sbyte)0x5F);              // ASCII: _
            Vector128<sbyte> shift5F = Vector128.Create((sbyte)33);                // high nibble is 0x5 -> range 'P' .. 'Z' for shift, not '+' (0x2)
            Vector128<sbyte> shuffleConstant0 = Vector128.Create(0x01400140).AsSByte();
            Vector128<short> shuffleConstant1 = Vector128.Create(0x00011000).AsInt16();
            Vector128<sbyte> shuffleVec = ReadVector128(SseDecodeShuffleVec);

            do
            {
                Vector128<sbyte> str = ReadVector128(ref src);

                Vector128<sbyte> hiNibbles = Sse2.And(Sse2.ShiftRightLogical(str.AsInt32(), 4).AsSByte(), mask5F);
                Vector128<sbyte> lowerBound = Ssse3.Shuffle(lutLo, hiNibbles);
                Vector128<sbyte> upperBound = Ssse3.Shuffle(lutHi, hiNibbles);

                Vector128<sbyte> below = Sse2.CompareLessThan(str, lowerBound);
                Vector128<sbyte> above = Sse2.CompareGreaterThan(str, upperBound);
                Vector128<sbyte> eq5F = Sse2.CompareEqual(str, mask5F);
                Vector128<sbyte> outside = Sse2.AndNot(eq5F, Sse2.Or(below, above));

                if (Sse2.MoveMask(outside) != 0)
                    break;

                Vector128<sbyte> shift = Ssse3.Shuffle(lutShift, hiNibbles);
                str = Sse2.Add(str, shift);
                str = Sse2.Add(str, Sse2.And(eq5F, shift5F));

                Vector128<short> merge_ab_and_bc = Ssse3.MultiplyAddAdjacent(str.AsByte(), shuffleConstant0);
                Vector128<int> @out = Sse2.MultiplyAddAdjacent(merge_ab_and_bc, shuffleConstant1);
                str = Ssse3.Shuffle(@out.AsSByte(), shuffleVec);

                WriteVector128(ref dest, str);

                src = ref Unsafe.Add(ref src, 16);
                dest = ref Unsafe.Add(ref dest, 12);
            }
            while (Unsafe.IsAddressLessThan(ref src, ref simdSrcEnd));

            // Cast to ulong to avoid the overflow-check. Codegen for x86 is still good.
            sourceIndex = (uint)(ulong)Unsafe.ByteOffset(ref srcStart, ref src);
            destIndex = (uint)(ulong)Unsafe.ByteOffset(ref destStart, ref dest);
        }

        private const sbyte lInv = 1;       // any value so that a comparison < results in true for invalid values
        private const sbyte hInv = 0x00;

        private static ReadOnlySpan<sbyte> SseDecodeLutLo => new sbyte[16]
        {
            lInv, lInv, 0x2D, 0x30,
            0x41, 0x50, 0x61, 0x70,
            lInv, lInv, lInv, lInv,
            lInv, lInv, lInv, lInv
        };

        private static ReadOnlySpan<sbyte> SseDecodeLutHi => new sbyte[16]
        {
            hInv, hInv, 0x2D, 0x39,
            0x4F, 0x5A, 0x6F, 0x7A,
            hInv, hInv, hInv, hInv,
            hInv, hInv, hInv, hInv
        };

        private static ReadOnlySpan<sbyte> SseDecodeLutShift => new sbyte[16]
        {
            0,   0,  17,   4,
            -65, -65, -71, -71,
            0,   0,   0,   0,
            0,   0,   0,   0
        };
#endif

        public int GetEncodedLength(int sourceLength)
        {
            int numPaddingChars = GetNumBase64PaddingCharsAddedByEncode(sourceLength);
            int base64EncodedLength = GetBase64EncodedLength(sourceLength);

            return base64EncodedLength - numPaddingChars;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GetNumBase64PaddingCharsAddedByEncode(int dataLength)
        {
            // Calculation is:
            // switch (dataLength % 3)
            // 0 -> 0
            // 1 -> 2
            // 2 -> 1
            uint mod3 = FastMod3((uint)dataLength);
            return (int)(mod3 == 0 ? 0 : 3 - mod3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GetBase64EncodedLength(int sourceLength)
        {
            if ((uint)sourceLength > 1610612733)
                ThrowHelper.ThrowArgumentOutOfRangeException();

            return (int)FastDiv3(sourceLength + 2) * 4;
        }

        public OperationStatus TryEncode(ReadOnlySpan<byte> data, Span<byte> encoded, out int consumed, out int written)
        {
            if (data.IsEmpty)
            {
                consumed = 0;
                written = 0;
                return OperationStatus.Done;
            }

            int srcLength = data.Length;
            ref byte srcBytes = ref MemoryMarshal.GetReference(data);
            ref byte dest = ref MemoryMarshal.GetReference(encoded);

            int encodedLength = GetEncodedLength(srcLength);

            return TryEncode(ref srcBytes, srcLength, ref dest, encoded.Length, encodedLength, out consumed, out written);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private OperationStatus TryEncode(
            ref byte srcBytes,
            int srcLength,
            ref byte dest,
            int destLength,
            int encodedLength,
            out int consumed,
            out int written)
        {
            uint sourceIndex = 0;
            uint destIndex = 0;
            int maxSrcLength;

            if (srcLength <= 1610612733 && destLength >= encodedLength)
                maxSrcLength = srcLength;
            else
                maxSrcLength = (destLength >> 2) * 3;

#if NETCOREAPP3_0
            if (Ssse3.IsSupported && maxSrcLength >= 16)
            {
                if (Avx2.IsSupported && maxSrcLength >= 32)
                {
                    Avx2Encode(ref srcBytes, ref dest, maxSrcLength, ref sourceIndex, ref destIndex);

                    if (sourceIndex == srcLength)
                        goto DoneExit;
                }

                if (Ssse3.IsSupported && (maxSrcLength >= (int)sourceIndex + 16))
                {
                    Ssse3Encode(ref srcBytes, ref dest, maxSrcLength, ref sourceIndex, ref destIndex);

                    if (sourceIndex == srcLength)
                        goto DoneExit;
                }
            }
#endif

            maxSrcLength -= 2;
            ref byte encodingMap = ref MemoryMarshal.GetReference(EncodingMap);

            // In order to elide the movsxd in the loop
            if (sourceIndex < maxSrcLength)
            {
                do
                {
                    EncodeThreeBytes(ref Unsafe.Add(ref srcBytes, (IntPtr)sourceIndex), ref Unsafe.Add(ref dest, (IntPtr)destIndex), ref encodingMap);
                    destIndex += 4;
                    sourceIndex += 3;
                }
                while (sourceIndex < (uint)maxSrcLength);
            }

            if (maxSrcLength != srcLength - 2)
                goto DestinationTooSmallExit;

            if (sourceIndex == srcLength - 1)
            {
                EncodeOneByte(ref Unsafe.Add(ref srcBytes, (IntPtr)sourceIndex), ref Unsafe.Add(ref dest, (IntPtr)destIndex), ref encodingMap);
                destIndex += 2;
                sourceIndex += 1;
            }
            else if (sourceIndex == srcLength - 2)
            {
                EncodeTwoBytes(ref Unsafe.Add(ref srcBytes, (IntPtr)sourceIndex), ref Unsafe.Add(ref dest, (IntPtr)destIndex), ref encodingMap);
                destIndex += 3;
                sourceIndex += 2;
            }

#if NETCOREAPP3_0
        DoneExit:
#endif
            consumed = (int)sourceIndex;
            written = (int)destIndex;
            return OperationStatus.Done;

        DestinationTooSmallExit:
            consumed = (int)sourceIndex;
            written = (int)destIndex;
            return OperationStatus.DestinationTooSmall;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void EncodeTwoBytes(ref byte twoBytes, ref byte encoded, ref byte encodingMap)
        {
            uint i = (uint)twoBytes << 16 | (uint)Unsafe.Add(ref twoBytes, 1) << 8;

            uint i0 = Unsafe.Add(ref encodingMap, (IntPtr)(i >> 18));
            uint i1 = Unsafe.Add(ref encodingMap, (IntPtr)((i >> 12) & 0x3F));
            uint i2 = Unsafe.Add(ref encodingMap, (IntPtr)((i >> 6) & 0x3F));

            Unsafe.Add(ref encoded, 0) = (byte)i0;
            Unsafe.Add(ref encoded, 1) = (byte)i1;
            Unsafe.Add(ref encoded, 2) = (byte)i2;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void EncodeOneByte(ref byte oneByte, ref byte encoded, ref byte encodingMap)
        {
            uint i = (uint)oneByte << 8;

            uint i0 = Unsafe.Add(ref encodingMap, (IntPtr)(i >> 10));
            uint i1 = Unsafe.Add(ref encodingMap, (IntPtr)((i >> 4) & 0x3F));

            Unsafe.Add(ref encoded, 0) = (byte)i0;
            Unsafe.Add(ref encoded, 1) = (byte)i1;
        }

        private static ReadOnlySpan<byte> EncodingMap
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                ReadOnlySpan<byte> map = new byte[64 + 1] {
                    0,      // https://github.com/dotnet/coreclr/issues/23194
                    65, 66, 67, 68, 69, 70, 71, 72,         //A..H
                    73, 74, 75, 76, 77, 78, 79, 80,         //I..P
                    81, 82, 83, 84, 85, 86, 87, 88,         //Q..X
                    89, 90, 97, 98, 99, 100, 101, 102,      //Y..Z, a..f
                    103, 104, 105, 106, 107, 108, 109, 110, //g..n
                    111, 112, 113, 114, 115, 116, 117, 118, //o..v
                    119, 120, 121, 122, 48, 49, 50, 51,     //w..z, 0..3
                    52, 53, 54, 55, 56, 57, 45, 95          //4..9, -, _
                };

                // Slicing is necessary to "unlink" the ref and let the JIT keep it in a register
                return map.Slice(1);
            }
        }

#if NETCOREAPP3_0
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Avx2Encode(ref byte src, ref byte dest, int sourceLength, ref uint sourceIndex, ref uint destIndex)
        {
            ref byte srcStart = ref src;
            ref byte destStart = ref dest;
            ref byte simdSrcEnd = ref Unsafe.Add(ref src, (IntPtr)((uint)sourceLength - 32));   // no +1 as the comparison is >

            // The JIT won't hoist these "constants", so help it
            Vector256<sbyte> shuffleVec = ReadVector256(AvxEncodeShuffleVec);
            Vector256<sbyte> shuffleConstant0 = Vector256.Create(0x0fc0fc00).AsSByte();
            Vector256<sbyte> shuffleConstant2 = Vector256.Create(0x003f03f0).AsSByte();
            Vector256<ushort> shuffleConstant1 = Vector256.Create(0x04000040).AsUInt16();
            Vector256<short> shuffleConstant3 = Vector256.Create(0x01000010).AsInt16();
            Vector256<byte> translationContant0 = Vector256.Create((byte)51);
            Vector256<sbyte> translationContant1 = Vector256.Create((sbyte)25);
            Vector256<sbyte> lut = ReadVector256(AvxEncodeLut);

            // first load is done at c-0 not to get a segfault
            Vector256<sbyte> str = ReadVector256(ref src);

            // shift by 4 bytes, as required by enc_reshuffle
            str = Avx2.PermuteVar8x32(str.AsInt32(), ReadVector256(AvxEncodePermuteVec).AsInt32()).AsSByte();

            // Next loads are at c-4, so shift it once
            src = ref Unsafe.Subtract(ref src, 4);

            while (true)
            {
                // Reshuffle
                str = Avx2.Shuffle(str, shuffleVec);
                Vector256<sbyte> t0 = Avx2.And(str, shuffleConstant0);
                Vector256<sbyte> t2 = Avx2.And(str, shuffleConstant2);
                Vector256<ushort> t1 = Avx2.MultiplyHigh(t0.AsUInt16(), shuffleConstant1);
                Vector256<short> t3 = Avx2.MultiplyLow(t2.AsInt16(), shuffleConstant3);
                str = Avx2.Or(t1.AsSByte(), t3.AsSByte());

                // Translation
                Vector256<byte> indices = Avx2.SubtractSaturate(str.AsByte(), translationContant0);
                Vector256<sbyte> mask = Avx2.CompareGreaterThan(str, translationContant1);
                Vector256<sbyte> tmp = Avx2.Subtract(indices.AsSByte(), mask);
                str = Avx2.Add(str, Avx2.Shuffle(lut, tmp));

                WriteVector256(ref dest, str);

                src = ref Unsafe.Add(ref src, 24);
                dest = ref Unsafe.Add(ref dest, 32);

                if (Unsafe.IsAddressGreaterThan(ref src, ref simdSrcEnd))
                    break;

                // Load at c-4, as required by enc_reshuffle
                str = ReadVector256(ref src);
            }

            // Cast to ulong to avoid the overflow-check. Codegen for x86 is still good.
            sourceIndex = (uint)(ulong)Unsafe.ByteOffset(ref srcStart, ref src) + 4;
            destIndex = (uint)(ulong)Unsafe.ByteOffset(ref destStart, ref dest);
        }

        private static ReadOnlySpan<sbyte> AvxEncodeLut => new sbyte[]
        {
            65, 71, -4, -4,
            -4, -4, -4, -4,
            -4, -4, -4, -4,
            -17, 32,  0,  0,
            65, 71, -4, -4,
            -4, -4, -4, -4,
            -4, -4, -4, -4,
            -17, 32,  0,  0
        };

        // Originally this is of type int, but ROSpan<byte>for static data can handly (s)byte only
        // due to endianess concerns.
        private static ReadOnlySpan<sbyte> AvxEncodePermuteVec => new sbyte[32]
        {
            0, 0, 0, 0,
            0, 0, 0, 0,
            1, 0, 0, 0,
            2, 0, 0, 0,
            3, 0, 0, 0,
            4, 0, 0, 0,
            5, 0, 0, 0,
            6, 0, 0, 0
        };

        private static ReadOnlySpan<sbyte> AvxEncodeShuffleVec => new sbyte[32]
        {
            5,  4,  6,  5,
            8,  7,  9,  8,
            11, 10, 12, 11,
            14, 13, 15, 14,
            1,  0,  2,  1,
            4,  3,  5,  4,
            7,  6,  8,  7,
            10,  9, 11, 10
        };

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Ssse3Encode(ref byte src, ref byte dest, int sourceLength, ref uint sourceIndex, ref uint destIndex)
        {
            ref byte srcStart = ref src;
            ref byte destStart = ref dest;
            ref byte simdSrcEnd = ref Unsafe.Add(ref src, (IntPtr)((uint)sourceLength - 16 + 1));   //  +1 for <=

            // Shift to workspace
            src = ref Unsafe.Add(ref src, (IntPtr)sourceIndex);
            dest = ref Unsafe.Add(ref dest, (IntPtr)destIndex);

            // The JIT won't hoist these "constants", so help it
            Vector128<sbyte> shuffleVec = ReadVector128(SseEncodeShuffleVec);
            Vector128<sbyte> shuffleConstant0 = Vector128.Create(0x0fc0fc00).AsSByte();
            Vector128<sbyte> shuffleConstant2 = Vector128.Create(0x003f03f0).AsSByte();
            Vector128<ushort> shuffleConstant1 = Vector128.Create(0x04000040).AsUInt16();
            Vector128<short> shuffleConstant3 = Vector128.Create(0x01000010).AsInt16();
            Vector128<byte> translationContant0 = Vector128.Create((byte)51);
            Vector128<sbyte> translationContant1 = Vector128.Create((sbyte)25);
            Vector128<sbyte> lut = ReadVector128(SseEncodeLut);

            do
            {
                Vector128<sbyte> str = ReadVector128(ref src);

                // Reshuffle
                str = Ssse3.Shuffle(str, shuffleVec);
                Vector128<sbyte> t0 = Sse2.And(str, shuffleConstant0);
                Vector128<sbyte> t2 = Sse2.And(str, shuffleConstant2);
                Vector128<ushort> t1 = Sse2.MultiplyHigh(t0.AsUInt16(), shuffleConstant1);
                Vector128<short> t3 = Sse2.MultiplyLow(t2.AsInt16(), shuffleConstant3);
                str = Sse2.Or(t1.AsSByte(), t3.AsSByte());

                // Translation
                Vector128<byte> indices = Sse2.SubtractSaturate(str.AsByte(), translationContant0);
                Vector128<sbyte> mask = Sse2.CompareGreaterThan(str, translationContant1);
                Vector128<sbyte> tmp = Sse2.Subtract(indices.AsSByte(), mask);
                str = Sse2.Add(str, Ssse3.Shuffle(lut, tmp));

                WriteVector128(ref dest, str);

                src = ref Unsafe.Add(ref src, 12);
                dest = ref Unsafe.Add(ref dest, 16);
            }
            while (Unsafe.IsAddressLessThan(ref src, ref simdSrcEnd));

            // Cast to ulong to avoid the overflow-check. Codegen for x86 is still good.
            sourceIndex = (uint)(ulong)Unsafe.ByteOffset(ref srcStart, ref src);
            destIndex = (uint)(ulong)Unsafe.ByteOffset(ref destStart, ref dest);
        }

        private static ReadOnlySpan<sbyte> SseEncodeLut => new sbyte[]
        {
            65, 71, -4, -4,
            -4, -4, -4, -4,
            -4, -4, -4, -4,
            -17, 32,  0,  0
        };

        private static ReadOnlySpan<sbyte> SseEncodeShuffleVec => new sbyte[16]
        {
            1,  0,  2,  1,
            4,  3,  5,  4,
            7,  6,  8,  7,
            10,  9, 11, 10
        };

        private static ReadOnlySpan<sbyte> SseDecodeShuffleVec => new sbyte[16]
        {
            2,  1,  0,  6,
            5,  4, 10,  9,
            8, 14, 13, 12,
            -1, -1, -1, -1
        };
#endif

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void EncodeThreeBytes(ref byte threeBytes, ref byte encoded, ref byte encodingMap)
        {
            uint t0 = threeBytes;
            uint t1 = Unsafe.Add(ref threeBytes, 1);
            uint t2 = Unsafe.Add(ref threeBytes, 2);

            uint i = (t0 << 16) | (t1 << 8) | t2;

            uint i0 = Unsafe.Add(ref encodingMap, (IntPtr)(i >> 18));
            uint i1 = Unsafe.Add(ref encodingMap, (IntPtr)((i >> 12) & 0x3F));
            uint i2 = Unsafe.Add(ref encodingMap, (IntPtr)((i >> 6) & 0x3F));
            uint i3 = Unsafe.Add(ref encodingMap, (IntPtr)(i & 0x3F));

            i = i0 | (i1 << 8) | (i2 << 16) | (i3 << 24);
            Unsafe.WriteUnaligned(ref encoded, i);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint FastMod3(uint value)
        {
            // Using fastmod from Daniel Lemire https://lemire.me/blog/2019/02/08/faster-remainders-when-the-divisor-is-a-constant-beating-compilers-and-libdivide/
            ulong lowBits = 6148914691236517206UL * value;
            uint high;
#if NETCOREAPP3_0
            if (Bmi2.X64.IsSupported)
            {
                high = (uint)Bmi2.X64.MultiplyNoFlags(lowBits, 3);
            }
            else
#endif
            {
                // 64bit * 64bit => 128bit isn't currently supported by Math https://github.com/dotnet/corefx/issues/41822
                // otherwise we'd want this to be (uint)Math.MultiplyHigh(lowbits, divisor)
                high = (uint)(((((ulong)(uint)lowBits * 3) >> 32) + ((lowBits >> 32) * 3)) >> 32);
            }

            Debug.Assert(high == value % 3);
            return high;
        }

        // Replace the divide by 3 by an optimized version
        // value / 3;
        //   L0000: mov ecx, 0x55555556
        //   L0005: mov eax, ecx
        //   L0007: imul edx
        //   L0009: mov eax, edx
        //   L000b: shr eax, 0x1f
        //   L000e: add eax, edx
        //   L0010: movsxd rax, eax
        // 
        // (0xAAAAAAABUL * (uint)value) >> 33;
        //   L0000: mov eax, edx
        //   L0002: mov edx, 0xaaaaaaab
        //   L0007: imul rax, rdx
        //   L000b: shr rax, 0x21
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint FastDiv3(int value)
        {
            return (uint)((0xAAAAAAABUL * (uint)value) >> 33);
        }

#if NETCOREAPP3_0
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<sbyte> ReadVector128(ReadOnlySpan<sbyte> data)
        {
            ref sbyte tmp = ref MemoryMarshal.GetReference(data);
            return Unsafe.As<sbyte, Vector128<sbyte>>(ref tmp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<sbyte> ReadVector128(ref byte src)
        {
            return Unsafe.As<byte, Vector128<sbyte>>(ref src);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void WriteVector128(ref byte dest, Vector128<sbyte> vec)
        {
            Unsafe.As<byte, Vector128<sbyte>>(ref dest) = vec;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<sbyte> ReadVector256(ReadOnlySpan<sbyte> data)
        {
            ref sbyte tmp = ref MemoryMarshal.GetReference(data);
            return Unsafe.As<sbyte, Vector256<sbyte>>(ref tmp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<sbyte> ReadVector256(ref byte src)
        {
            return Unsafe.As<byte, Vector256<sbyte>>(ref src);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void WriteVector256(ref byte dest, Vector256<sbyte> vec)
        {
            // As has better CQ than WriteUnaligned
            // https://github.com/dotnet/coreclr/issues/21132
            Unsafe.As<byte, Vector256<sbyte>>(ref dest) = vec;
        }

        // There is no intrinsics for that
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<sbyte> LessThan(Vector256<sbyte> left, Vector256<sbyte> right, Vector256<sbyte> allOnes)
        {
            // (a < b) = ~(a > b) & ~(a = b) = ~((a > b) | (a = b))
            Vector256<sbyte> eq = Avx2.CompareEqual(left, right);
            Vector256<sbyte> gt = Avx2.CompareGreaterThan(left, right);
            Vector256<sbyte> or = Avx2.Or(eq, gt);

            // -1 = 0xFF = true in simd
            return Avx2.AndNot(or, allOnes);
        }
#endif
    }
}