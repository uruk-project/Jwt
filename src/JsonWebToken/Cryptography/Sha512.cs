// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Computes SHA2-512 hash values.
    /// </summary>
    public class Sha512 : Sha2
    {
        private const int Sha512HashSize = 64;
        private const int Sha512BlockSize = 128;

        /// <summary>
        /// Gets the default instance of the <see cref="Sha512"/> class.
        /// </summary>
        public static readonly Sha512 Shared = new Sha512();

        /// <inheritsdoc />
        public override int HashSize => Sha512HashSize;

        /// <inheritsdoc />
        public override int BlockSize => Sha512BlockSize;

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend, Span<uint> W)
        {
            throw new NotImplementedException();
        }

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend, Span<ulong> w)
        {
            if (destination.Length < Sha512HashSize)
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, Sha512HashSize);
            }

            // init
            Span<ulong> state = stackalloc ulong[] {
                0x6a09e667f3bcc908ul,
                0xbb67ae8584caa73bul,
                0x3c6ef372fe94f82bul,
                0xa54ff53a5f1d36f1ul,
                0x510e527fade682d1ul,
                0x9b05688c2b3e6c1ful,
                0x1f83d9abfb41bd6bul,
                0x5be0cd19137e2179ul
            };
            int dataLength = source.Length + prepend.Length;
            int remaining = dataLength & (Sha512BlockSize - 1);
            Span<byte> lastBlock = stackalloc byte[Sha512BlockSize];
            ref byte lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

            // update
            Span<ulong> wTemp = w.IsEmpty ? stackalloc ulong[80] : w;
            ref ulong wRef = ref MemoryMarshal.GetReference(wTemp);
            ref ulong stateRef = ref MemoryMarshal.GetReference(state);
            ref byte srcStartRef = ref MemoryMarshal.GetReference(source);
            ref byte srcRef = ref srcStartRef;
            if (!prepend.IsEmpty)
            {
                if (prepend.Length == Sha512BlockSize)
                {
                    // Consider the prepend as the first block
                    Transform(ref stateRef, ref MemoryMarshal.GetReference(prepend), ref wRef);
                }
                else if (prepend.Length < Sha512BlockSize)
                {
                    // Copy the prepend into the buffer
                    Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref MemoryMarshal.GetReference(prepend), (uint)prepend.Length);
                    int srcRemained = Sha512BlockSize - prepend.Length;
                    if (dataLength >= Sha512BlockSize)
                    {
                        // Copy the fist bytes of the source into the buffer, transform this block and increment the source offset
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)srcRemained);
                        Transform(ref stateRef, ref lastBlockRef, ref wRef);
                        srcRef = ref Unsafe.Add(ref srcRef, (IntPtr)srcRemained);
                    }
                    else
                    {
                        // Copy the source into the buffer and go to the padding part of the hashing
                        Unsafe.CopyBlockUnaligned(ref Unsafe.Add(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)source.Length);
                        goto Padding;
                    }
                }
                else
                {
                    ThrowHelper.ThrowArgumentException_PrependMustBeLessOrEqualToBlockSize(prepend, Sha512BlockSize);
                }
            }

            ref byte srcEndRef = ref Unsafe.Add(ref srcStartRef, (IntPtr)(source.Length - Sha512BlockSize + 1));
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            if (Avx2.IsSupported)
            {
                ref byte srcSimdEndRef = ref Unsafe.Add(ref srcStartRef, (IntPtr)(source.Length - 4 * Sha512BlockSize + 1));
                if (Unsafe.IsAddressLessThan(ref srcRef, ref srcSimdEndRef))
                {
                    Vector256<ulong>[] returnToPool;
                    Span<Vector256<ulong>> wAvx = (returnToPool = ArrayPool<Vector256<ulong>>.Shared.Rent(80));
                    try
                    {
                        ref Vector256<ulong> w4Ref = ref MemoryMarshal.GetReference(wAvx);
                        do
                        {
                            Transform(ref stateRef, ref srcRef, ref w4Ref);
                            srcRef = ref Unsafe.Add(ref srcRef, Sha512BlockSize * 4);
                        } while (Unsafe.IsAddressLessThan(ref srcRef, ref srcSimdEndRef));
                    }
                    finally
                    {
                        ArrayPool<Vector256<ulong>>.Shared.Return(returnToPool);
                    }
                }
            }
#endif

            while (Unsafe.IsAddressLessThan(ref srcRef, ref srcEndRef))
            {
                Transform(ref stateRef, ref srcRef, ref wRef);
                srcRef = ref Unsafe.Add(ref srcRef, Sha512BlockSize);
            }

            // final
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref srcRef, (uint)remaining);

        Padding:
            // Pad the last block
            Unsafe.Add(ref lastBlockRef, (IntPtr)remaining) = 0x80;
            lastBlock.Slice(remaining + 1).Clear();
            if (remaining >= Sha512BlockSize - 2 * sizeof(ulong))
            {
                Transform(ref stateRef, ref lastBlockRef, ref wRef);
                lastBlock.Slice(0, Sha512BlockSize - 2 * sizeof(ulong)).Clear();
            }

            // Append to the padding the total message's length in bits and transform.
            ulong bitLength = (ulong)dataLength << 3;
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref lastBlockRef, Sha512BlockSize - 16), 0ul); // Don't support input length > 2^64
            Unsafe.WriteUnaligned(ref Unsafe.Add(ref lastBlockRef, Sha512BlockSize - 8), BinaryPrimitives.ReverseEndianness(bitLength));
            Transform(ref stateRef, ref lastBlockRef, ref wRef);

            // reverse all the bytes when copying the final state to the output hash.
            ref byte destinationRef = ref MemoryMarshal.GetReference(destination);
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            if (Avx2.IsSupported)
            {
                var littleEndianMask = ReadVector256(LittleEndianMask);
                Unsafe.WriteUnaligned(ref destinationRef, Avx2.Shuffle(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.As<ulong, byte>(ref stateRef)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 32), Avx2.Shuffle(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref Unsafe.As<ulong, byte>(ref stateRef), 32)), littleEndianMask));
            }
            else if (Ssse3.IsSupported)
            {
                var littleEndianMask = ReadVector128(LittleEndianMask);
                Unsafe.WriteUnaligned(ref destinationRef, Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.As<ulong, byte>(ref stateRef)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref Unsafe.As<ulong, byte>(ref stateRef), 16)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 32), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref Unsafe.As<ulong, byte>(ref stateRef), 32)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 48), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref Unsafe.As<ulong, byte>(ref stateRef), 48)), littleEndianMask));
            }
            else
#endif
            {
                Unsafe.WriteUnaligned(ref destinationRef, BinaryPrimitives.ReverseEndianness(stateRef));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 8), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 1)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 16), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 2)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 24), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 3)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 32), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 4)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 40), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 5)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 48), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 6)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref destinationRef, 56), BinaryPrimitives.ReverseEndianness(Unsafe.Add(ref stateRef, 7)));
            }
        }

#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
        internal static ReadOnlySpan<byte> GatherMask => new byte[16]
        {
            0, 0, 0, 0,
            16, 0, 0, 0,
            32, 0, 0, 0,
            48, 0, 0, 0,
        };

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe Vector256<ulong> Gather(ref byte message, Vector128<int> gatherMask)
        {
            return Avx2.GatherVector256((ulong*)Unsafe.AsPointer(ref message), gatherMask, 8);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> Sigma0(Vector256<ulong> W)
        {
            return Avx2.Xor(Avx2.Xor(Avx2.Xor(Avx2.ShiftRightLogical(W, 7), Avx2.ShiftRightLogical(W, 8)), Avx2.Xor(Avx2.ShiftRightLogical(W, 1), Avx2.ShiftLeftLogical(W, 56))), Avx2.ShiftLeftLogical(W, 63));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> Sigma1(Vector256<ulong> W)
        {
            return Avx2.Xor(Avx2.Xor(Avx2.Xor(Avx2.ShiftRightLogical(W, 6), Avx2.ShiftRightLogical(W, 61)), Avx2.Xor(Avx2.ShiftRightLogical(W, 19), Avx2.ShiftLeftLogical(W, 3))), Avx2.ShiftLeftLogical(W, 45));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> Schedule(Vector256<ulong> w0, Vector256<ulong> w1, Vector256<ulong> w9, Vector256<ulong> w14, IntPtr i, ref Vector256<ulong> schedule)
        {
            Unsafe.Add(ref schedule, i) = Avx2.Add(w0, K256(i));
            return Avx2.Add(Avx2.Add(w0, w9), Avx2.Add(Sigma0(w1), Sigma1(w14)));
        }

        private static void Schedule(ref Vector256<ulong> schedule, ref byte message)
        {
            IntPtr i = (IntPtr)0;
            Vector256<ulong> W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
            var littleEndianMask = ReadVector256(LittleEndianMask);
            var gatherMask = ReadVector128(GatherMask).AsInt32();
            W0 = Avx2.Shuffle(Gather(ref message, gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W1 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 1), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W2 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 2), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W3 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 3), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W4 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 4), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W5 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 5), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W6 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 6), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W7 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 7), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W8 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 8), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W9 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 9), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W10 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 10), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W11 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 11), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W12 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 12), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W13 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 13), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W14 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 14), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            W15 = Avx2.Shuffle(Gather(ref Unsafe.Add(ref message, 8 * 15), gatherMask).AsByte(), littleEndianMask).AsUInt64();
            Schedule(ref schedule, ref i, ref W0, ref W1, ref W2, ref W3, ref W4, ref W5, ref W6, ref W7, ref W8, ref W9, ref W10, ref W11, ref W12, ref W13, ref W14, ref W15);

            Unsafe.Add(ref schedule, 64) = Avx2.Add(W0, K256((IntPtr)64));
            Unsafe.Add(ref schedule, 65) = Avx2.Add(W1, K256((IntPtr)65));
            Unsafe.Add(ref schedule, 66) = Avx2.Add(W2, K256((IntPtr)66));
            Unsafe.Add(ref schedule, 67) = Avx2.Add(W3, K256((IntPtr)67));
            Unsafe.Add(ref schedule, 68) = Avx2.Add(W4, K256((IntPtr)68));
            Unsafe.Add(ref schedule, 69) = Avx2.Add(W5, K256((IntPtr)69));
            Unsafe.Add(ref schedule, 70) = Avx2.Add(W6, K256((IntPtr)70));
            Unsafe.Add(ref schedule, 71) = Avx2.Add(W7, K256((IntPtr)71));
            Unsafe.Add(ref schedule, 72) = Avx2.Add(W8, K256((IntPtr)72));
            Unsafe.Add(ref schedule, 73) = Avx2.Add(W9, K256((IntPtr)73));
            Unsafe.Add(ref schedule, 74) = Avx2.Add(W10, K256((IntPtr)74));
            Unsafe.Add(ref schedule, 75) = Avx2.Add(W11, K256((IntPtr)75));
            Unsafe.Add(ref schedule, 76) = Avx2.Add(W12, K256((IntPtr)76));
            Unsafe.Add(ref schedule, 77) = Avx2.Add(W13, K256((IntPtr)77));
            Unsafe.Add(ref schedule, 78) = Avx2.Add(W14, K256((IntPtr)78));
            Unsafe.Add(ref schedule, 79) = Avx2.Add(W15, K256((IntPtr)79));
        }

        private static unsafe void Schedule(ref Vector256<ulong> schedule, ref IntPtr i, ref Vector256<ulong> W0, ref Vector256<ulong> W1, ref Vector256<ulong> W2, ref Vector256<ulong> W3, ref Vector256<ulong> W4, ref Vector256<ulong> W5, ref Vector256<ulong> W6, ref Vector256<ulong> W7, ref Vector256<ulong> W8, ref Vector256<ulong> W9, ref Vector256<ulong> W10, ref Vector256<ulong> W11, ref Vector256<ulong> W12, ref Vector256<ulong> W13, ref Vector256<ulong> W14, ref Vector256<ulong> W15)
        {
            do
            {
                W0 = Schedule(W0, W1, W9, W14, i, ref schedule);
                i += 1;
                W1 = Schedule(W1, W2, W10, W15, i, ref schedule);
                i += 1;
                W2 = Schedule(W2, W3, W11, W0, i, ref schedule);
                i += 1;
                W3 = Schedule(W3, W4, W12, W1, i, ref schedule);
                i += 1;
                W4 = Schedule(W4, W5, W13, W2, i, ref schedule);
                i += 1;
                W5 = Schedule(W5, W6, W14, W3, i, ref schedule);
                i += 1;
                W6 = Schedule(W6, W7, W15, W4, i, ref schedule);
                i += 1;
                W7 = Schedule(W7, W8, W0, W5, i, ref schedule);
                i += 1;
                W8 = Schedule(W8, W9, W1, W6, i, ref schedule);
                i += 1;
                W9 = Schedule(W9, W10, W2, W7, i, ref schedule);
                i += 1;
                W10 = Schedule(W10, W11, W3, W8, i, ref schedule);
                i += 1;
                W11 = Schedule(W11, W12, W4, W9, i, ref schedule);
                i += 1;
                W12 = Schedule(W12, W13, W5, W10, i, ref schedule);
                i += 1;
                W13 = Schedule(W13, W14, W6, W11, i, ref schedule);
                i += 1;
                W14 = Schedule(W14, W15, W7, W12, i, ref schedule);
                i += 1;
                W15 = Schedule(W15, W0, W8, W13, i, ref schedule);
                i += 1;
            }
            while ((byte*)i < (byte*)64);
        }

        internal static unsafe void Transform(ref ulong state, ref byte currentBlock, ref Vector256<ulong> w)
        {
            ref ulong wEnd = ref Unsafe.As<Vector256<ulong>, ulong>(ref Unsafe.Add(ref w, 80));
            ulong a, b, c, d, e, f, g, h;
            Schedule(ref w, ref currentBlock);
            for (IntPtr j = (IntPtr)0; (byte*)j < (byte*)4; j += 1)
            {
                a = state;
                b = Unsafe.Add(ref state, 1);
                c = Unsafe.Add(ref state, 2);
                d = Unsafe.Add(ref state, 3);
                e = Unsafe.Add(ref state, 4);
                f = Unsafe.Add(ref state, 5);
                g = Unsafe.Add(ref state, 6);
                h = Unsafe.Add(ref state, 7);
                ref ulong w0 = ref Unsafe.Add(ref Unsafe.As<Vector256<ulong>, ulong>(ref w), j);
                do
                {
                    Round(a, b, c, ref d, e, f, g, ref h, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(h, a, b, ref c, d, e, f, ref g, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(g, h, a, ref b, c, d, e, ref f, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(f, g, h, ref a, b, c, d, ref e, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(e, f, g, ref h, a, b, c, ref d, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(d, e, f, ref g, h, a, b, ref c, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(c, d, e, ref f, g, h, a, ref b, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                    Round(b, c, d, ref e, f, g, h, ref a, w0);
                    w0 = ref Unsafe.Add(ref w0, 4);
                }
                while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

                state += a;
                Unsafe.Add(ref state, 1) += b;
                Unsafe.Add(ref state, 2) += c;
                Unsafe.Add(ref state, 3) += d;
                Unsafe.Add(ref state, 4) += e;
                Unsafe.Add(ref state, 5) += f;
                Unsafe.Add(ref state, 6) += g;
                Unsafe.Add(ref state, 7) += h;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(ulong a, ulong b, ulong c, ref ulong d, ulong e, ulong f, ulong g, ref ulong h, ulong w)
        {
            h += BigSigma1(e) + Ch(e, f, g) + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }
#endif

        internal static void Transform(ref ulong state, ref byte currentBlock, ref ulong w)
        {
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            ref byte wRef = ref Unsafe.As<ulong, byte>(ref w);
            if (Avx2.IsSupported)
            {
                var littleEndianMask = ReadVector256(LittleEndianMask);
                Unsafe.WriteUnaligned(ref wRef, Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref currentBlock), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 32)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 64), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 64)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 96), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref currentBlock, 96)), littleEndianMask));
            }
            else if (Ssse3.IsSupported)
            {
                var littleEndianMask = ReadVector128(LittleEndianMask);
                Unsafe.WriteUnaligned(ref wRef, Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref currentBlock), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 16), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 16)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 32), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 32)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 48), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 48)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 64), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 64)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 80), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 80)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 96), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 96)), littleEndianMask));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref wRef, 112), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref currentBlock, 112)), littleEndianMask));
            }
            else
#endif
            {
                unsafe
                {
                    for (IntPtr i = (IntPtr)0, j = (IntPtr)0; (byte*)i < (byte*)16; i += 1, j += sizeof(ulong))
                    {
                        //for (int i = 0, j = 0; i < 16; ++i, j += 8)
                        Unsafe.Add(ref w, i) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref currentBlock, j)));
                    }
                }
            }

            ref ulong wEnd = ref Unsafe.Add(ref w, 80);
            ref ulong w0 = ref Unsafe.Add(ref w, 16);
            do
            {
                w0 = Unsafe.Subtract(ref w0, 16) + Sigma0(Unsafe.Subtract(ref w0, 15)) + Unsafe.Subtract(ref w0, 7) + Sigma1(Unsafe.Subtract(ref w0, 2));
                Unsafe.Add(ref w0, 1) = Unsafe.Subtract(ref w0, 15) + Sigma0(Unsafe.Subtract(ref w0, 14)) + Unsafe.Subtract(ref w0, 6) + Sigma1(Unsafe.Subtract(ref w0, 1));
                w0 = ref Unsafe.Add(ref w0, 2);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            ulong a = state;
            ulong b = Unsafe.Add(ref state, 1);
            ulong c = Unsafe.Add(ref state, 2);
            ulong d = Unsafe.Add(ref state, 3);
            ulong e = Unsafe.Add(ref state, 4);
            ulong f = Unsafe.Add(ref state, 5);
            ulong g = Unsafe.Add(ref state, 6);
            ulong h = Unsafe.Add(ref state, 7);
            w0 = ref w;
            ref ulong k0 = ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(K));
            do
            {
                Round(a, b, c, ref d, e, f, g, ref h, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(h, a, b, ref c, d, e, f, ref g, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(g, h, a, ref b, c, d, e, ref f, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(f, g, h, ref a, b, c, d, ref e, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(e, f, g, ref h, a, b, c, ref d, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(d, e, f, ref g, h, a, b, ref c, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(c, d, e, ref f, g, h, a, ref b, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
                Round(b, c, d, ref e, f, g, h, ref a, w0, k0);
                w0 = ref Unsafe.Add(ref w0, 1);
                k0 = ref Unsafe.Add(ref k0, 1);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            state += a;
            Unsafe.Add(ref state, 1) += b;
            Unsafe.Add(ref state, 2) += c;
            Unsafe.Add(ref state, 3) += d;
            Unsafe.Add(ref state, 4) += e;
            Unsafe.Add(ref state, 5) += f;
            Unsafe.Add(ref state, 6) += g;
            Unsafe.Add(ref state, 7) += h;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Round(ulong a, ulong b, ulong c, ref ulong d, ulong e, ulong f, ulong g, ref ulong h, ulong w, ulong k)
        {
            h += BigSigma1(e) + Ch(e, f, g) + k + w;
            d += h;
            h += BigSigma0(a) + Maj(a, b, c);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong RotateRight(ulong a, byte b)
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            => BitOperations.RotateRight(a, b);
#else
            => (a >> b) | (a << (64 - b));
#endif

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong BigSigma0(ulong a)
             => RotateRight(a, 28) ^ RotateRight(a, 34) ^ RotateRight(a, 39);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong BigSigma1(ulong e)
            => RotateRight(e, 14) ^ RotateRight(e, 18) ^ RotateRight(e, 41);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Sigma0(ulong w)
            => RotateRight(w, 1) ^ RotateRight(w, 8) ^ (w >> 7);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Sigma1(ulong w)
            => RotateRight(w, 19) ^ RotateRight(w, 61) ^ (w >> 6);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Ch(ulong x, ulong y, ulong z)
            => z ^ (x & (y ^ z));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Maj(ulong x, ulong y, ulong z)
            => ((x | y) & z) | (x & y);

        internal static ReadOnlySpan<byte> K => new byte[20 * 4 * 8]
        {
            34, 174, 40, 215, 152, 47, 138, 66,
            205, 101, 239, 35, 145, 68, 55, 113,
            47, 59, 77, 236, 207, 251, 192, 181,
            188, 219, 137, 129, 165, 219, 181, 233,
            56, 181, 72, 243, 91, 194, 86, 57,
            25, 208, 5, 182, 241, 17, 241, 89,
            155, 79, 25, 175, 164, 130, 63, 146,
            24, 129, 109, 218, 213, 94, 28, 171,
            66, 2, 3, 163, 152, 170, 7, 216,
            190, 111, 112, 69, 1, 91, 131, 18,
            140, 178, 228, 78, 190, 133, 49, 36,
            226, 180, 255, 213, 195, 125, 12, 85,
            111, 137, 123, 242, 116, 93, 190, 114,
            177, 150, 22, 59, 254, 177, 222, 128,
            53, 18, 199, 37, 167, 6, 220, 155,
            148, 38, 105, 207, 116, 241, 155, 193,
            210, 74, 241, 158, 193, 105, 155, 228,
            227, 37, 79, 56, 134, 71, 190, 239,
            181, 213, 140, 139, 198, 157, 193, 15,
            101, 156, 172, 119, 204, 161, 12, 36,
            117, 2, 43, 89, 111, 44, 233, 45,
            131, 228, 166, 110, 170, 132, 116, 74,
            212, 251, 65, 189, 220, 169, 176, 92,
            181, 83, 17, 131, 218, 136, 249, 118,
            171, 223, 102, 238, 82, 81, 62, 152,
            16, 50, 180, 45, 109, 198, 49, 168,
            63, 33, 251, 152, 200, 39, 3, 176,
            228, 14, 239, 190, 199, 127, 89, 191,
            194, 143, 168, 61, 243, 11, 224, 198,
            37, 167, 10, 147, 71, 145, 167, 213,
            111, 130, 3, 224, 81, 99, 202, 6,
            112, 110, 14, 10, 103, 41, 41, 20,
            252, 47, 210, 70, 133, 10, 183, 39,
            38, 201, 38, 92, 56, 33, 27, 46,
            237, 42, 196, 90, 252, 109, 44, 77,
            223, 179, 149, 157, 19, 13, 56, 83,
            222, 99, 175, 139, 84, 115, 10, 101,
            168, 178, 119, 60, 187, 10, 106, 118,
            230, 174, 237, 71, 46, 201, 194, 129,
            59, 53, 130, 20, 133, 44, 114, 146,
            100, 3, 241, 76, 161, 232, 191, 162,
            1, 48, 66, 188, 75, 102, 26, 168,
            145, 151, 248, 208, 112, 139, 75, 194,
            48, 190, 84, 6, 163, 81, 108, 199,
            24, 82, 239, 214, 25, 232, 146, 209,
            16, 169, 101, 85, 36, 6, 153, 214,
            42, 32, 113, 87, 133, 53, 14, 244,
            184, 209, 187, 50, 112, 160, 106, 16,
            200, 208, 210, 184, 22, 193, 164, 25,
            83, 171, 65, 81, 8, 108, 55, 30,
            153, 235, 142, 223, 76, 119, 72, 39,
            168, 72, 155, 225, 181, 188, 176, 52,
            99, 90, 201, 197, 179, 12, 28, 57,
            203, 138, 65, 227, 74, 170, 216, 78,
            115, 227, 99, 119, 79, 202, 156, 91,
            163, 184, 178, 214, 243, 111, 46, 104,
            252, 178, 239, 93, 238, 130, 143, 116,
            96, 47, 23, 67, 111, 99, 165, 120,
            114, 171, 240, 161, 20, 120, 200, 132,
            236, 57, 100, 26, 8, 2, 199, 140,
            40, 30, 99, 35, 250, 255, 190, 144,
            233, 189, 130, 222, 235, 108, 80, 164,
            21, 121, 198, 178, 247, 163, 249, 190,
            43, 83, 114, 227, 242, 120, 113, 198,
            156, 97, 38, 234, 206, 62, 39, 202,
            7, 194, 192, 33, 199, 184, 134, 209,
            30, 235, 224, 205, 214, 125, 218, 234,
            120, 209, 110, 238, 127, 79, 125, 245,
            186, 111, 23, 114, 170, 103, 240, 6,
            166, 152, 200, 162, 197, 125, 99, 10,
            174, 13, 249, 190, 4, 152, 63, 17,
            27, 71, 28, 19, 53, 11, 113, 27,
            132, 125, 4, 35, 245, 119, 219, 40,
            147, 36, 199, 64, 123, 171, 202, 50,
            188, 190, 201, 21, 10, 190, 158, 60,
            76, 13, 16, 156, 196, 103, 29, 67,
            182, 66, 62, 203, 190, 212, 197, 76,
            42, 126, 101, 252, 156, 41, 127, 89,
            236, 250, 214, 58, 171, 111, 203, 95,
            23, 88, 71, 74, 140, 25, 68, 108
        };

#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> K256(IntPtr i)
            => Vector256.Create(Unsafe.Add(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(K)), i));
#endif
    }
}
