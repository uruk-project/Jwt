// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace JsonWebToken.Internal
{
    internal sealed class SoftwareBase64Url : IBase64Url
    {
        // Force init of map
        static SoftwareBase64Url()
        {
        }

        private const int MaximumEncodeLength = (int.MaxValue >> 2) * 3;

        public OperationStatus EncodeToUtf8(ReadOnlySpan<byte> data, Span<byte> encoded, out int bytesConsumed, out int bytesWritten)
        {
            ref byte srcBytes = ref MemoryMarshal.GetReference(data);
            ref byte destBytes = ref MemoryMarshal.GetReference(encoded);
            int srcLength = data.Length;
            int destLength = encoded.Length;
  
            int maxSrcLength;
            if (srcLength <= MaximumEncodeLength && destLength >= GetMaxEncodedToUtf8Length(srcLength))
            {
                maxSrcLength = srcLength - 2;
            }
            else
            {
                maxSrcLength = ((destLength >> 2) * 3) - 2;
            }

            int sourceIndex = 0;
            int destIndex = 0;

            ref byte encodingMap = ref s_encodingMap[0];

            while (sourceIndex < maxSrcLength)
            {
                int result = EncodeThreeBytes(ref Unsafe.Add(ref srcBytes, sourceIndex), ref encodingMap);
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destBytes, destIndex), result);
                destIndex += 4;
                sourceIndex += 3;
            }

            if (maxSrcLength != srcLength - 2)
                goto DestinationSmallExit;

            if (sourceIndex == srcLength - 1)
            {
                short result = EncodeOneByte(ref Unsafe.Add(ref srcBytes, sourceIndex), ref encodingMap);
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destBytes, destIndex), result);
                destIndex += 2;
                sourceIndex += 1;
            }
            else if (sourceIndex == srcLength - 2)
            {
                int result = EncodeTwoBytes(ref Unsafe.Add(ref srcBytes, sourceIndex), ref encodingMap);
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destBytes, destIndex), (short)result);
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destBytes, destIndex + 2), (byte)(result >> 16));
                destIndex += 3;
                sourceIndex += 2;
            }

            bytesConsumed = sourceIndex;
            bytesWritten = destIndex;
            return OperationStatus.Done;

            DestinationSmallExit:
            bytesConsumed = sourceIndex;
            bytesWritten = destIndex;
            return OperationStatus.DestinationTooSmall;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int GetMaxEncodedToUtf8Length(int length)
        {
            if ((uint)length > MaximumEncodeLength)
                JwtThrowHelper.ThrowArgumentOutOfRangeException();

            return (((length + 2) / 3) << 2) - GetNumBase64PaddingCharsAddedByEncode(length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GetNumBase64PaddingCharsAddedByEncode(int dataLength)
        {
            // Calculation is:
            // 0 -> 0
            // 1 -> 2
            // 2 -> 1
            return dataLength % 3 == 0 ? 0 : 3 - (dataLength % 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int EncodeThreeBytes(ref byte threeBytes, ref byte encodingMap)
        {
            int i = (threeBytes << 16)
                | (Unsafe.Add(ref threeBytes, 1) << 8)
                | Unsafe.Add(ref threeBytes, 2);

            int i0 = Unsafe.Add(ref encodingMap, i >> 18);
            int i1 = Unsafe.Add(ref encodingMap, (i >> 12) & 0x3F);
            int i2 = Unsafe.Add(ref encodingMap, (i >> 6) & 0x3F);
            int i3 = Unsafe.Add(ref encodingMap, i & 0x3F);

            return i0 | (i1 << 8) | (i2 << 16) | (i3 << 24);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int EncodeTwoBytes(ref byte twoBytes, ref byte encodingMap)
        {
            int i = (twoBytes << 16)
                | (Unsafe.Add(ref twoBytes, 1) << 8);

            int i0 = Unsafe.Add(ref encodingMap, i >> 18);
            int i1 = Unsafe.Add(ref encodingMap, (i >> 12) & 0x3F);
            int i2 = Unsafe.Add(ref encodingMap, (i >> 6) & 0x3F);

            return i0 | (i1 << 8) | (i2 << 16);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static short EncodeOneByte(ref byte oneByte, ref byte encodingMap)
        {
            int i = (oneByte << 8);

            int i0 = Unsafe.Add(ref encodingMap, i >> 10);
            int i1 = Unsafe.Add(ref encodingMap, (i >> 4) & 0x3F);

            return (short)(i0 | (i1 << 8));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int GetMaxDecodedFromUtf8Length(int length)
        {
            var numPaddingChars = GetNumBase64PaddingCharsToAddForDecode(length);
            var base64Len = length + numPaddingChars;
            return ((base64Len >> 2) * 3) - numPaddingChars;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GetNumBase64PaddingCharsToAddForDecode(int urlEncodedLen)
        {
            // Calculation is:
            // 0 -> 0
            // 2 -> 2
            // 3 -> 1
            // default -> format exception

            var result = (4 - urlEncodedLen) & 3;

            if (result == 3)
            {
                JwtThrowHelper.ThrowMalformedInputException(urlEncodedLen);
            }

            return result;
        }
        public OperationStatus DecodeFromUtf8(ReadOnlySpan<byte> encoded, Span<byte> data, out int bytesConsumed, out int bytesWritten)
        {
            ref var source = ref MemoryMarshal.GetReference(encoded);
            ref var destBytes = ref MemoryMarshal.GetReference(data);

            var base64Len = GetBufferSizeRequiredToUrlDecode(encoded.Length, out int dataLength);
            var srcLength = base64Len & ~0x3;       // only decode input up to closest multiple of 4.
            var destLength = data.Length;

            var sourceIndex = 0;
            var destIndex = 0;

            if (encoded.Length == 0)
            {
                goto DoneExit;
            }

            ref var decodingMap = ref s_decodingMap[0];

            // Last bytes could have padding characters, so process them separately and treat them as valid only if isFinalBlock is true.
            // If isFinalBlock is false, padding characters are considered invalid.
            const int skipLastChunk = 4;

            int maxSrcLength;
            if (destLength >= dataLength)
            {
                maxSrcLength = srcLength - skipLastChunk;
            }
            else
            {
                // This should never overflow since destLength here is less than int.MaxValue / 4 * 3.
                // Therefore, (destLength / 3) * 4 will always be less than int.MaxValue.
                maxSrcLength = (destLength / 3) << 2;
            }

            while (sourceIndex < maxSrcLength)
            {
                var result = DecodeFour(ref Unsafe.Add(ref source, sourceIndex), ref decodingMap);

                if (result < 0) goto InvalidExit;

                WriteThreeLowOrderBytes(ref destBytes, destIndex, result);
                destIndex += 3;
                sourceIndex += 4;
            }

            if (maxSrcLength != srcLength - skipLastChunk)
            {
                goto DestinationSmallExit;
            }

            // If input is less than 4 bytes, srcLength == sourceIndex == 0
            // If input is not a multiple of 4, sourceIndex == srcLength != 0
            if (sourceIndex == srcLength)
            {
                goto InvalidExit;
            }

            // Handle last four bytes. There are 0, 1, 2 padding chars.
            var numPaddingChars = base64Len - encoded.Length;
            ref var lastFourStart = ref Unsafe.Add(ref source, srcLength - 4);

            if (numPaddingChars == 0)
            {
                var result = DecodeFour(ref lastFourStart, ref decodingMap);

                if (result < 0) goto InvalidExit;
                if (destIndex > destLength - 3) goto DestinationSmallExit;

                WriteThreeLowOrderBytes(ref destBytes, destIndex, result);
                destIndex += 3;
                sourceIndex += 4;
            }
            else if (numPaddingChars == 1)
            {
                var result = DecodeThree(ref lastFourStart, ref decodingMap);

                if (result < 0)
                {
                    goto InvalidExit;
                }

                if (destIndex > destLength - 2)
                {
                    goto DestinationSmallExit;
                }

                WriteTwoLowOrderBytes(ref destBytes, destIndex, result);
                destIndex += 2;
                sourceIndex += 3;
            }
            else
            {
                var result = DecodeTwo(ref lastFourStart, ref decodingMap);

                if (result < 0)
                {
                    goto InvalidExit;
                }

                if (destIndex > destLength - 1)
                {
                    goto DestinationSmallExit;
                }

                WriteOneLowOrderByte(ref destBytes, destIndex, result);
                destIndex += 1;
                sourceIndex += 2;
            }

            if (srcLength != base64Len)
            {
                goto InvalidExit;
            }

            DoneExit:
            bytesConsumed = sourceIndex;
            bytesWritten = destIndex;
            return OperationStatus.Done;

            DestinationSmallExit:
            if (srcLength != encoded.Length)
            {
                // if input is not a multiple of 4, and there is no more data, return invalid data instead
                goto InvalidExit;
            }
            bytesConsumed = sourceIndex;
            bytesWritten = destIndex;
            return OperationStatus.DestinationTooSmall;

            InvalidExit:
            bytesConsumed = sourceIndex;
            bytesWritten = destIndex;
            return OperationStatus.InvalidData;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int DecodeFour(ref byte encoded, ref sbyte decodingMap)
        {
            int i0, i1, i2, i3;

            ref var tmp = ref Unsafe.As<byte, byte>(ref encoded);
            i0 = Unsafe.Add(ref tmp, 0);
            i1 = Unsafe.Add(ref tmp, 1);
            i2 = Unsafe.Add(ref tmp, 2);
            i3 = Unsafe.Add(ref tmp, 3);

            i0 = Unsafe.Add(ref decodingMap, i0);
            i1 = Unsafe.Add(ref decodingMap, i1);
            i2 = Unsafe.Add(ref decodingMap, i2);
            i3 = Unsafe.Add(ref decodingMap, i3);

            return i0 << 18
                | i1 << 12
                | i2 << 6
                | i3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int DecodeThree(ref byte encoded, ref sbyte decodingMap)
        {
            int i0, i1, i2;

            ref var tmp = ref Unsafe.As<byte, byte>(ref encoded);
            i0 = Unsafe.Add(ref tmp, 0);
            i1 = Unsafe.Add(ref tmp, 1);
            i2 = Unsafe.Add(ref tmp, 2);

            i0 = Unsafe.Add(ref decodingMap, i0);
            i1 = Unsafe.Add(ref decodingMap, i1);
            i2 = Unsafe.Add(ref decodingMap, i2);

            return i0 << 18
                | i1 << 12
                | i2 << 6;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int DecodeTwo(ref byte encoded, ref sbyte decodingMap)
        {
            int i0, i1;

            ref var tmp = ref Unsafe.As<byte, byte>(ref encoded);
            i0 = Unsafe.Add(ref tmp, 0);
            i1 = Unsafe.Add(ref tmp, 1);

            i0 = Unsafe.Add(ref decodingMap, i0);
            i1 = Unsafe.Add(ref decodingMap, i1);

            return i0 << 18
                | i1 << 12;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void WriteThreeLowOrderBytes(ref byte destination, int destIndex, int value)
        {
            Unsafe.Add(ref destination, destIndex + 0) = (byte)(value >> 16);
            Unsafe.Add(ref destination, destIndex + 1) = (byte)(value >> 8);
            Unsafe.Add(ref destination, destIndex + 2) = (byte)value;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void WriteTwoLowOrderBytes(ref byte destination, int destIndex, int value)
        {
            Unsafe.Add(ref destination, destIndex + 0) = (byte)(value >> 16);
            Unsafe.Add(ref destination, destIndex + 1) = (byte)(value >> 8);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void WriteOneLowOrderByte(ref byte destination, int destIndex, int value)
        {
            Unsafe.Add(ref destination, destIndex) = (byte)(value >> 16);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GetBufferSizeRequiredToUrlDecode(int urlEncodedLen, out int dataLength)
        {
            var numPaddingChars = GetNumBase64PaddingCharsToAddForDecode(urlEncodedLen);
            var base64Len = urlEncodedLen + numPaddingChars;
            Debug.Assert(base64Len % 4 == 0, "Invariant: Array length must be a multiple of 4.");
            dataLength = ((base64Len >> 2) * 3) - numPaddingChars;

            return base64Len;
        }

        //---------------------------------------------------------------------
        private static readonly byte[] s_encodingMap = {
            65, 66, 67, 68, 69, 70, 71, 72,         //A..H
            73, 74, 75, 76, 77, 78, 79, 80,         //I..P
            81, 82, 83, 84, 85, 86, 87, 88,         //Q..X
            89, 90, 97, 98, 99, 100, 101, 102,      //Y..Z, a..f
            103, 104, 105, 106, 107, 108, 109, 110, //g..n
            111, 112, 113, 114, 115, 116, 117, 118, //o..v
            119, 120, 121, 122, 48, 49, 50, 51,     //w..z, 0..3
            52, 53, 54, 55, 56, 57, 45, 95          //4..9, -, _
        };

        private static readonly sbyte[] s_decodingMap =
        {
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
    }
}