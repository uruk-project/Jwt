using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#if NETCOREAPP
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

// Scalar based on https://github.com/dotnet/corefx/tree/master/src/System.Memory/src/System/Buffers/Text
// SSE2 based on https://github.com/aklomp/base64/tree/master/lib/arch/ssse3
// AVX2 based on https://github.com/aklomp/base64/tree/master/lib/arch/avx2

namespace gfoidl.Base64.Internal
{
    partial class Base64Encoder
    {
        public override int GetEncodedLength(int sourceLength) => GetBase64EncodedLength(sourceLength);
        //---------------------------------------------------------------------
        // PERF: can't be in base class due to inlining (generic virtual)
        public override unsafe string Encode(ReadOnlySpan<byte> data)
        {
#if NETCOREAPP
            // Threshoulds found by testing -- may not be ideal on all targets

            if (data.Length < 26)
                return Convert.ToBase64String(data);

            // Get the encoded length here, to avoid this compution in the above path
            int encodedLength = this.GetEncodedLength(data.Length);

            if (data.Length < 82)
            {
                char* ptr              = stackalloc char[encodedLength];
                ref char encoded       = ref Unsafe.AsRef<char>(ptr);
                ref byte srcBytes      = ref MemoryMarshal.GetReference(data);
                OperationStatus status = this.EncodeImpl(ref srcBytes, data.Length, ref encoded, encodedLength, encodedLength, out int consumed, out int written);

                Debug.Assert(status        == OperationStatus.Done);
                Debug.Assert(data.Length   == consumed);
                Debug.Assert(encodedLength == written);

                return new string(ptr, 0, written);
            }

            fixed (byte* ptr = data)
            {
                return string.Create(encodedLength, (Ptr: (IntPtr)ptr, data.Length), (encoded, state) =>
                {
                    ref byte srcBytes      = ref Unsafe.AsRef<byte>(state.Ptr.ToPointer());
                    ref char dest          = ref MemoryMarshal.GetReference(encoded);
                    OperationStatus status = this.EncodeImpl(ref srcBytes, state.Length, ref dest, encoded.Length, encoded.Length, out int consumed, out int written);

                    Debug.Assert(status         == OperationStatus.Done);
                    Debug.Assert(state.Length   == consumed);
                    Debug.Assert(encoded.Length == written);
                });
            }
#else
            if (data.IsEmpty)
                return string.Empty;

            int encodedLength          = this.GetEncodedLength(data.Length);
            char[] arrayToReturnToPool = null;

            Span<char> encoded = encodedLength <= MaxStackallocBytes / sizeof(char)
                ? stackalloc char[encodedLength]
                : arrayToReturnToPool = ArrayPool<char>.Shared.Rent(encodedLength);

            try
            {
                OperationStatus status = this.EncodeImpl(data, encoded, out int consumed, out int written, encodedLength);
                Debug.Assert(status         == OperationStatus.Done);
                Debug.Assert(data.Length    == consumed);
                Debug.Assert(encoded.Length >= written);

                fixed (char* ptr = encoded)
                    return new string(ptr, 0, written);
            }
            finally
            {
                if (arrayToReturnToPool != null)
                    ArrayPool<char>.Shared.Return(arrayToReturnToPool);
            }
#endif
        }
        //---------------------------------------------------------------------
        // PERF: can't be in base class due to inlining (generic virtual)
        protected override OperationStatus EncodeCore(
            ReadOnlySpan<byte> data,
            Span<byte> encoded,
            out int consumed,
            out int written,
            int encodedLength = -1,
            bool isFinalBlock = true)
            => this.EncodeImpl(data, encoded, out consumed, out written, encodedLength, isFinalBlock);
        //---------------------------------------------------------------------
        // PERF: can't be in base class due to inlining (generic virtual)
        protected override OperationStatus EncodeCore(
            ReadOnlySpan<byte> data,
            Span<char> encoded,
            out int consumed,
            out int written,
            int encodedLength = -1,
            bool isFinalBlock = true)
            => this.EncodeImpl(data, encoded, out consumed, out written, encodedLength, isFinalBlock);
        //---------------------------------------------------------------------
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private OperationStatus EncodeImpl<T>(
            ReadOnlySpan<byte> data,
            Span<T> encoded,
            out int consumed,
            out int written,
            int encodedLength = -1,
            bool isFinalBlock = true)
        {
            if (data.IsEmpty)
            {
                consumed = 0;
                written  = 0;
                return OperationStatus.Done;
            }

            int srcLength     = data.Length;
            ref byte srcBytes = ref MemoryMarshal.GetReference(data);
            ref T dest        = ref MemoryMarshal.GetReference(encoded);

            if (encodedLength == -1)
                encodedLength = this.GetEncodedLength(srcLength);

            return this.EncodeImpl(ref srcBytes, srcLength, ref dest, encoded.Length, encodedLength, out consumed, out written, isFinalBlock);
        }
        //---------------------------------------------------------------------
#if NETCOREAPP3_0
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
#endif
        private OperationStatus EncodeImpl<T>(
            ref byte srcBytes,
            int srcLength,
            ref T dest,
            int destLength,
            int encodedLength,
            out int consumed,
            out int written,
            bool isFinalBlock = true)
        {
            uint sourceIndex = 0;
            uint destIndex   = 0;

#if NETCOREAPP
            if (srcLength < 16)
                goto Scalar;
#endif

#if NETCOREAPP3_0
            if (Avx2.IsSupported && srcLength >= 32 && !s_isMac)
            {
                Avx2Encode(ref srcBytes, ref dest, srcLength, ref sourceIndex, ref destIndex);

                if (sourceIndex == srcLength)
                    goto DoneExit;
            }
#endif

#if NETCOREAPP
#if NETCOREAPP3_0
            if (Ssse3.IsSupported && ((uint)srcLength - 16 >= sourceIndex))
#else
            if (Sse2.IsSupported && Ssse3.IsSupported && ((uint)srcLength - 16 >= sourceIndex))
#endif
            {
                Sse2Encode(ref srcBytes, ref dest, srcLength, ref sourceIndex, ref destIndex);

                if (sourceIndex == srcLength)
                    goto DoneExit;
            }

        Scalar:
#endif
            int maxSrcLength = -2;

            if (srcLength <= MaximumEncodeLength && destLength >= encodedLength)
                maxSrcLength += srcLength;
            else
                maxSrcLength += (destLength >> 2) * 3;

            ref byte encodingMap = ref s_encodingMap[0];

            // In order to elide the movsxd in the loop
            if (sourceIndex < maxSrcLength)
            {
                do
                {
                    EncodeThreeBytes(ref Unsafe.Add(ref srcBytes, (IntPtr)sourceIndex), ref Unsafe.Add(ref dest, (IntPtr)destIndex), ref encodingMap);
                    destIndex   += 4;
                    sourceIndex += 3;
                }
                while (sourceIndex < (uint)maxSrcLength);
            }

            if (maxSrcLength != srcLength - 2)
                goto DestinationSmallExit;

            if (!isFinalBlock)
                goto NeedMoreDataExit;

            if (sourceIndex == srcLength - 1)
            {
                EncodeOneByte(ref Unsafe.Add(ref srcBytes, (IntPtr)sourceIndex), ref Unsafe.Add(ref dest, (IntPtr)destIndex), ref encodingMap);
                destIndex   += 4;
                sourceIndex += 1;
            }
            else if (sourceIndex == srcLength - 2)
            {
                EncodeTwoBytes(ref Unsafe.Add(ref srcBytes, (IntPtr)sourceIndex), ref Unsafe.Add(ref dest, (IntPtr)destIndex), ref encodingMap);
                destIndex   += 4;
                sourceIndex += 2;
            }
#if NETCOREAPP
        DoneExit:
#endif
            consumed = (int)sourceIndex;
            written  = (int)destIndex;
            return OperationStatus.Done;

        NeedMoreDataExit:
            consumed = (int)sourceIndex;
            written  = (int)destIndex;
            return OperationStatus.NeedMoreData;

        DestinationSmallExit:
            consumed = (int)sourceIndex;
            written  = (int)destIndex;
            return OperationStatus.DestinationTooSmall;
        }
        //---------------------------------------------------------------------
#if NETCOREAPP3_0
#if DEBUG
        public static event EventHandler<EventArgs> Avx2Encoded;
#endif
        //---------------------------------------------------------------------
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Avx2Encode<T>(ref byte src, ref T dest, int sourceLength, ref uint sourceIndex, ref uint destIndex)
        {
            ref byte srcStart   = ref src;
            ref T destStart     = ref dest;
            ref byte simdSrcEnd = ref Unsafe.Add(ref src, (IntPtr)((uint)sourceLength - 28 + 1));

            // The JIT won't hoist these "constants", so help him
            Vector256<sbyte> shuffleVec          = s_avx_encodeShuffleVec;
            Vector256<sbyte> shuffleConstant0    = Avx.StaticCast<int, sbyte>(Avx.SetAllVector256(0x0fc0fc00));
            Vector256<sbyte> shuffleConstant2    = Avx.StaticCast<int, sbyte>(Avx.SetAllVector256(0x003f03f0));
            Vector256<ushort> shuffleConstant1   = Avx.StaticCast<int, ushort>(Avx.SetAllVector256(0x04000040));
            Vector256<short> shuffleConstant3    = Avx.StaticCast<int, short>(Avx.SetAllVector256(0x01000010));
            Vector256<byte> translationContant0  = Avx.SetAllVector256((byte)51);
            Vector256<sbyte> translationContant1 = Avx.SetAllVector256((sbyte)25);
            Vector256<sbyte> lut                 = s_avx_encodeLut;

            // first load is done at c-0 not to get a segfault
            Vector256<sbyte> str = Unsafe.ReadUnaligned<Vector256<sbyte>>(ref src);

            // shift by 4 bytes, as required by enc_reshuffle
            str = Avx.StaticCast<int, sbyte>(Avx2.PermuteVar8x32(
                Avx.StaticCast<sbyte, int>(str),
                s_avx_encodePermuteVec));

            while (true)
            {
                // Reshuffle
                str                  = Avx2.Shuffle(str, shuffleVec);
                Vector256<sbyte>  t0 = Avx2.And(str, shuffleConstant0);
                Vector256<sbyte>  t2 = Avx2.And(str, shuffleConstant2);
                Vector256<ushort> t1 = Avx2.MultiplyHigh(Avx.StaticCast<sbyte, ushort>(t0), shuffleConstant1);
                Vector256<short>  t3 = Avx2.MultiplyLow(Avx.StaticCast<sbyte, short>(t2), shuffleConstant3);
                str                  = Avx2.Or(Avx.StaticCast<ushort, sbyte>(t1), Avx.StaticCast<short, sbyte>(t3));

                // Translation
                Vector256<byte>  indices = Avx2.SubtractSaturate(Avx.StaticCast<sbyte, byte>(str), translationContant0);
                Vector256<sbyte> mask    = Avx2.CompareGreaterThan(str, translationContant1);
                Vector256<sbyte> tmp     = Avx2.Subtract(Avx.StaticCast<byte, sbyte>(indices), mask);
                str                      = Avx2.Add(str, Avx2.Shuffle(lut, tmp));

                if (typeof(T) == typeof(byte))
                {
                    // As has better CQ than WriteUnaligned
                    // https://github.com/dotnet/coreclr/issues/21132
                    Unsafe.As<T, Vector256<sbyte>>(ref dest) = str;
                }
                else if (typeof(T) == typeof(char))
                {
                    Avx2Helper.Write(str, ref Unsafe.As<T, char>(ref dest));
                }
                else
                {
                    throw new NotSupportedException(); // just in case new types are introduced in the future
                }

                src  = ref Unsafe.Add(ref src,  24);
                dest = ref Unsafe.Add(ref dest, 32);

                if (Unsafe.IsAddressGreaterThan(ref src, ref simdSrcEnd))
                    break;

                // Load at c-4, as required by enc_reshuffle
                str = Unsafe.ReadUnaligned<Vector256<sbyte>>(ref Unsafe.Subtract(ref src, 4));
            }

            // Cast to ulong to avoid the overflow-check. Codegen for x86 is still good.
            sourceIndex = (uint)(ulong)Unsafe.ByteOffset(ref srcStart,  ref src);
            destIndex   = (uint)(ulong)Unsafe.ByteOffset(ref destStart, ref dest) / (uint)Unsafe.SizeOf<T>();

            src  = ref srcStart;
            dest = ref destStart;
#if DEBUG
            Avx2Encoded?.Invoke(null, EventArgs.Empty);
#endif
        }
#endif
        //---------------------------------------------------------------------
#if NETCOREAPP
#if DEBUG
        public static event EventHandler<EventArgs> Sse2Encoded;
#endif
        //---------------------------------------------------------------------
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Sse2Encode<T>(ref byte src, ref T dest, int sourceLength, ref uint sourceIndex, ref uint destIndex)
        {
            ref byte srcStart   = ref src;
            ref T destStart     = ref dest;
            ref byte simdSrcEnd = ref Unsafe.Add(ref src, (IntPtr)((uint)sourceLength - 16 + 1));

            // Shift to workspace
            src  = ref Unsafe.Add(ref src , (IntPtr)sourceIndex);
            dest = ref Unsafe.Add(ref dest, (IntPtr)destIndex);

            // The JIT won't hoist these "constants", so help him
            Vector128<sbyte>  shuffleVec          = s_sse_encodeShuffleVec;
            Vector128<sbyte>  shuffleConstant0    = Sse.StaticCast<int, sbyte>(Sse2.SetAllVector128(0x0fc0fc00));
            Vector128<sbyte>  shuffleConstant2    = Sse.StaticCast<int, sbyte>(Sse2.SetAllVector128(0x003f03f0));
            Vector128<ushort> shuffleConstant1    = Sse.StaticCast<int, ushort>(Sse2.SetAllVector128(0x04000040));
            Vector128<short>  shuffleConstant3    = Sse.StaticCast<int, short>(Sse2.SetAllVector128(0x01000010));
            Vector128<byte>   translationContant0 = Sse2.SetAllVector128((byte)51);
            Vector128<sbyte>  translationContant1 = Sse2.SetAllVector128((sbyte)25);
            Vector128<sbyte>  lut                 = s_sse_encodeLut;

            //while (remaining >= 16)
            while (Unsafe.IsAddressLessThan(ref src, ref simdSrcEnd))
            {
                Vector128<sbyte> str = Unsafe.ReadUnaligned<Vector128<sbyte>>(ref src);

                // Reshuffle
                str                  = Ssse3.Shuffle(str, shuffleVec);
                Vector128<sbyte>  t0 = Sse2.And(str, shuffleConstant0);
                Vector128<sbyte>  t2 = Sse2.And(str, shuffleConstant2);
                Vector128<ushort> t1 = Sse2.MultiplyHigh(Sse.StaticCast<sbyte, ushort>(t0), shuffleConstant1);
                Vector128<short>  t3 = Sse2.MultiplyLow(Sse.StaticCast<sbyte, short>(t2), shuffleConstant3);
                str                  = Sse2.Or(Sse.StaticCast<ushort, sbyte>(t1), Sse.StaticCast<short, sbyte>(t3));

                // Translation
                Vector128<byte>  indices = Sse2.SubtractSaturate(Sse.StaticCast<sbyte, byte>(str), translationContant0);
                Vector128<sbyte> mask    = Sse2.CompareGreaterThan(str, translationContant1);
                Vector128<sbyte> tmp     = Sse2.Subtract(Sse.StaticCast<byte, sbyte>(indices), mask);
                str                      = Sse2.Add(str, Ssse3.Shuffle(lut, tmp));

                if (typeof(T) == typeof(byte))
                {
                    // As has better CQ than WriteUnaligned
                    // https://github.com/dotnet/coreclr/issues/21132
                    Unsafe.As<T, Vector128<sbyte>>(ref dest) = str;
                }
                else if (typeof(T) == typeof(char))
                {
#if NETCOREAPP3_0
                    // https://github.com/dotnet/coreclr/issues/21130
                    //Vector128<sbyte> zero = Vector128<sbyte>.Zero;
                    Vector128<sbyte> zero = Sse2.SetZeroVector128<sbyte>();
#else
                    Vector128<sbyte> zero = Sse2.SetZeroVector128<sbyte>();
#endif
                    Vector128<sbyte> c0   = Sse2.UnpackLow(str, zero);
                    Vector128<sbyte> c1   = Sse2.UnpackHigh(str, zero);

                    // As has better CQ than WriteUnaligned
                    // https://github.com/dotnet/coreclr/issues/21132
                    Unsafe.As<T, Vector128<sbyte>>(ref dest)                    = c0;
                    Unsafe.As<T, Vector128<sbyte>>(ref Unsafe.Add(ref dest, 8)) = c1;
                }
                else
                {
                    throw new NotSupportedException(); // just in case new types are introduced in the future
                }

                src  = ref Unsafe.Add(ref src,  12);
                dest = ref Unsafe.Add(ref dest, 16);
            }

            // Cast to ulong to avoid the overflow-check. Codegen for x86 is still good.
            sourceIndex = (uint)(ulong)Unsafe.ByteOffset(ref srcStart, ref src);
            destIndex   = (uint)(ulong)Unsafe.ByteOffset(ref destStart, ref dest) / (uint)Unsafe.SizeOf<T>();

            src  = ref srcStart;
            dest = ref destStart;
#if DEBUG
            Sse2Encoded?.Invoke(null, EventArgs.Empty);
#endif
        }
#endif
        //---------------------------------------------------------------------
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void EncodeTwoBytes<T>(ref byte twoBytes, ref T encoded, ref byte encodingMap)
        {
            uint i = (uint)twoBytes << 16
                | (uint)Unsafe.Add(ref twoBytes, 1) << 8;

            uint i0 = Unsafe.Add(ref encodingMap, (IntPtr)(i >> 18));
            uint i1 = Unsafe.Add(ref encodingMap, (IntPtr)((i >> 12) & 0x3F));
            uint i2 = Unsafe.Add(ref encodingMap, (IntPtr)((i >> 6) & 0x3F));

            if (typeof(T) == typeof(byte))
            {
                i = i0 | (i1 << 8) | (i2 << 16) | (EncodingPad << 24);
                Unsafe.WriteUnaligned(ref Unsafe.As<T, byte>(ref encoded), i);
            }
            else if (typeof(T) == typeof(char))
            {
                ref char enc = ref Unsafe.As<T, char>(ref encoded);
                Unsafe.Add(ref enc, 0) = (char)i0;
                Unsafe.Add(ref enc, 1) = (char)i1;
                Unsafe.Add(ref enc, 2) = (char)i2;
                Unsafe.Add(ref enc, 3) = (char)EncodingPad;
            }
            else
            {
                throw new NotSupportedException();  // just in case new types are introduced in the future
            }
        }
        //---------------------------------------------------------------------
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void EncodeOneByte<T>(ref byte oneByte, ref T encoded, ref byte encodingMap)
        {
            uint i = (uint)oneByte << 8;

            uint i0 = Unsafe.Add(ref encodingMap, (IntPtr)(i >> 10));
            uint i1 = Unsafe.Add(ref encodingMap, (IntPtr)((i >> 4) & 0x3F));

            if (typeof(T) == typeof(byte))
            {
                i = i0 | (i1 << 8) | (EncodingPad << 16) | (EncodingPad << 24);
                Unsafe.WriteUnaligned(ref Unsafe.As<T, byte>(ref encoded), i);
            }
            else if (typeof(T) == typeof(char))
            {
                ref char enc = ref Unsafe.As<T, char>(ref encoded);
                Unsafe.Add(ref enc, 0) = (char)i0;
                Unsafe.Add(ref enc, 1) = (char)i1;
                Unsafe.Add(ref enc, 2) = (char)EncodingPad;
                Unsafe.Add(ref enc, 3) = (char)EncodingPad;
            }
            else
            {
                throw new NotSupportedException();  // just in case new types are introduced in the future
            }
        }
        //---------------------------------------------------------------------
#if NETCOREAPP
        private static readonly Vector128<sbyte> s_sse_encodeLut;
#if NETCOREAPP3_0
        private static readonly Vector256<sbyte> s_avx_encodeLut;
#endif
#endif
        // internal because tests use this map too
        internal static readonly byte[] s_encodingMap = {
            65, 66, 67, 68, 69, 70, 71, 72,         //A..H
            73, 74, 75, 76, 77, 78, 79, 80,         //I..P
            81, 82, 83, 84, 85, 86, 87, 88,         //Q..X
            89, 90, 97, 98, 99, 100, 101, 102,      //Y..Z, a..f
            103, 104, 105, 106, 107, 108, 109, 110, //g..n
            111, 112, 113, 114, 115, 116, 117, 118, //o..v
            119, 120, 121, 122, 48, 49, 50, 51,     //w..z, 0..3
            52, 53, 54, 55, 56, 57, 43, 47          //4..9, +, /
        };
    }
}
