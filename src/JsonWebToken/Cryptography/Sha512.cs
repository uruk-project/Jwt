﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
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
                    if (dataLength >= Sha512BlockSize)
                    {
                        // Copy the fist bytes of the source into the buffer, transform this block and increment the source offset
                        int srcRemained = Sha512BlockSize - prepend.Length;
                        Unsafe.CopyBlockUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)srcRemained);
                        Transform(ref stateRef, ref lastBlockRef, ref wRef);
                        srcRef = ref Unsafe.AddByteOffset(ref srcRef, (IntPtr)srcRemained);
                    }
                    else
                    {
                        // Copy the source into the buffer and go to the padding part of the hashing
                        Unsafe.CopyBlockUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)source.Length);
                        goto Padding;
                    }
                }
                else
                {
                    ThrowHelper.ThrowArgumentException_PrependMustBeLessOrEqualToBlockSize(prepend, Sha512BlockSize);
                }
            }

            ref byte srcEndRef = ref Unsafe.AddByteOffset(ref srcStartRef, (IntPtr)(source.Length - Sha512BlockSize + 1));
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            if (Avx2.IsSupported)
            {
                ref byte srcSimdEndRef = ref Unsafe.AddByteOffset(ref srcStartRef, (IntPtr)(source.Length - 4 * Sha512BlockSize + 1));
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
                            srcRef = ref Unsafe.AddByteOffset(ref srcRef, (IntPtr)(Sha512BlockSize * 4));
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
                srcRef = ref Unsafe.AddByteOffset(ref srcRef, (IntPtr)Sha512BlockSize);
            }

            // final
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref srcRef, (uint)remaining);

        Padding:
            // Pad the last block
            Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)remaining) = 0x80;
            lastBlock.Slice(remaining + 1).Clear();
            if (remaining >= Sha512BlockSize - 2 * sizeof(ulong))
            {
                Transform(ref stateRef, ref lastBlockRef, ref wRef);
                lastBlock.Slice(0, Sha512BlockSize - 2 * sizeof(ulong)).Clear();
            }

            // Append to the padding the total message's length in bits and transform.
            ulong bitLength = (ulong)dataLength << 3;
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)(Sha512BlockSize - 16)), 0ul); // Don't support input length > 2^64
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)(Sha512BlockSize - 8)), BinaryPrimitives.ReverseEndianness(bitLength));
            Transform(ref stateRef, ref lastBlockRef, ref wRef);

            // reverse all the bytes when copying the final state to the output hash.
            ref byte destinationRef = ref MemoryMarshal.GetReference(destination);
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Avx2.Shuffle(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.As<ulong, byte>(ref stateRef)), _littleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)32), Avx2.Shuffle(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.AddByteOffset(ref Unsafe.As<ulong, byte>(ref stateRef), (IntPtr)32)), _littleEndianMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.As<ulong, byte>(ref stateRef)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)16), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref Unsafe.As<ulong, byte>(ref stateRef), (IntPtr)16)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)32), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref Unsafe.As<ulong, byte>(ref stateRef), (IntPtr)32)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)48), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref Unsafe.As<ulong, byte>(ref stateRef), (IntPtr)48)), _littleEndianMask128));
            }
            else
#endif
            {
                Unsafe.WriteUnaligned(ref destinationRef, BinaryPrimitives.ReverseEndianness(stateRef));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)8), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)8)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)16), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)16)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)24), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)24)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)32), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)32)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)40), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)40)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)48), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)48)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)56), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)56)));
            }
        }

#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
        internal static Vector256<long> GatherMask = Vector256.Create(0L, 16, 32, 48);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe Vector256<ulong> Gather(ref byte message)
        {
            return Avx2.GatherVector256((ulong*)Unsafe.AsPointer(ref message), GatherMask, 8);
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
            Unsafe.AddByteOffset(ref schedule, i) = Avx2.Add(w0, K256(i));
            return Avx2.Add(Avx2.Add(w0, w9), Avx2.Add(Sigma0(w1), Sigma1(w14)));
        }

        internal unsafe static void Schedule(ref Vector256<ulong> schedule, ref byte message)
        {
            IntPtr i = (IntPtr)0;
            Vector256<ulong> W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
            W0 = Avx2.Shuffle(Gather(ref message).AsByte(), _littleEndianMask256).AsUInt64();
            W1 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)8)).AsByte(), _littleEndianMask256).AsUInt64();
            W2 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)16)).AsByte(), _littleEndianMask256).AsUInt64();
            W3 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)24)).AsByte(), _littleEndianMask256).AsUInt64();
            W4 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)32)).AsByte(), _littleEndianMask256).AsUInt64();
            W5 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)40)).AsByte(), _littleEndianMask256).AsUInt64();
            W6 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)48)).AsByte(), _littleEndianMask256).AsUInt64();
            W7 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)56)).AsByte(), _littleEndianMask256).AsUInt64();
            W8 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)64)).AsByte(), _littleEndianMask256).AsUInt64();
            W9 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)72)).AsByte(), _littleEndianMask256).AsUInt64();
            W10 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)80)).AsByte(), _littleEndianMask256).AsUInt64();
            W11 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)88)).AsByte(), _littleEndianMask256).AsUInt64();
            W12 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)96)).AsByte(), _littleEndianMask256).AsUInt64();
            W13 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)104)).AsByte(), _littleEndianMask256).AsUInt64();
            W14 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)112)).AsByte(), _littleEndianMask256).AsUInt64();
            W15 = Avx2.Shuffle(Gather(ref Unsafe.AddByteOffset(ref message, (IntPtr)120)).AsByte(), _littleEndianMask256).AsUInt64();
            do
            {
                W0 = Schedule(W0, W1, W9, W14, i, ref schedule);
                i += 32;
                W1 = Schedule(W1, W2, W10, W15, i, ref schedule);
                i += 32;
                W2 = Schedule(W2, W3, W11, W0, i, ref schedule);
                i += 32;
                W3 = Schedule(W3, W4, W12, W1, i, ref schedule);
                i += 32;
                W4 = Schedule(W4, W5, W13, W2, i, ref schedule);
                i += 32;
                W5 = Schedule(W5, W6, W14, W3, i, ref schedule);
                i += 32;
                W6 = Schedule(W6, W7, W15, W4, i, ref schedule);
                i += 32;
                W7 = Schedule(W7, W8, W0, W5, i, ref schedule);
                i += 32;
                W8 = Schedule(W8, W9, W1, W6, i, ref schedule);
                i += 32;
                W9 = Schedule(W9, W10, W2, W7, i, ref schedule);
                i += 32;
                W10 = Schedule(W10, W11, W3, W8, i, ref schedule);
                i += 32;
                W11 = Schedule(W11, W12, W4, W9, i, ref schedule);
                i += 32;
                W12 = Schedule(W12, W13, W5, W10, i, ref schedule);
                i += 32;
                W13 = Schedule(W13, W14, W6, W11, i, ref schedule);
                i += 32;
                W14 = Schedule(W14, W15, W7, W12, i, ref schedule);
                i += 32;
                W15 = Schedule(W15, W0, W8, W13, i, ref schedule);
                i += 32;
            }
            while ((byte*)i < (byte*)(64 * 32));

            Unsafe.AddByteOffset(ref schedule, (IntPtr)(64 * 32)) = Avx2.Add(W0, K256((IntPtr)(64 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(65 * 32)) = Avx2.Add(W1, K256((IntPtr)(65 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(66 * 32)) = Avx2.Add(W2, K256((IntPtr)(66 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(67 * 32)) = Avx2.Add(W3, K256((IntPtr)(67 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(68 * 32)) = Avx2.Add(W4, K256((IntPtr)(68 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(69 * 32)) = Avx2.Add(W5, K256((IntPtr)(69 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(70 * 32)) = Avx2.Add(W6, K256((IntPtr)(70 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(71 * 32)) = Avx2.Add(W7, K256((IntPtr)(71 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(72 * 32)) = Avx2.Add(W8, K256((IntPtr)(72 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(73 * 32)) = Avx2.Add(W9, K256((IntPtr)(73 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(74 * 32)) = Avx2.Add(W10, K256((IntPtr)(74 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(75 * 32)) = Avx2.Add(W11, K256((IntPtr)(75 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(76 * 32)) = Avx2.Add(W12, K256((IntPtr)(76 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(77 * 32)) = Avx2.Add(W13, K256((IntPtr)(77 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(78 * 32)) = Avx2.Add(W14, K256((IntPtr)(78 * 32)));
            Unsafe.AddByteOffset(ref schedule, (IntPtr)(79 * 32)) = Avx2.Add(W15, K256((IntPtr)(79 * 32)));
        }

        internal unsafe static void Transform(ref ulong state, ref byte currentBlock, ref Vector256<ulong> w)
        {
            ref ulong wEnd = ref Unsafe.As<Vector256<ulong>, ulong>(ref Unsafe.AddByteOffset(ref w, (IntPtr)(80 * 32)));
            ulong a, b, c, d, e, f, g, h;
            Schedule(ref w, ref currentBlock);
            for (IntPtr j = (IntPtr)0; (byte*)j < (byte*)32; j += 8)
            {
                a = state;
                b = Unsafe.AddByteOffset(ref state, (IntPtr)8);
                c = Unsafe.AddByteOffset(ref state, (IntPtr)16);
                d = Unsafe.AddByteOffset(ref state, (IntPtr)24);
                e = Unsafe.AddByteOffset(ref state, (IntPtr)32);
                f = Unsafe.AddByteOffset(ref state, (IntPtr)40);
                g = Unsafe.AddByteOffset(ref state, (IntPtr)48);
                h = Unsafe.AddByteOffset(ref state, (IntPtr)56);
                ref ulong w0 = ref Unsafe.AddByteOffset(ref Unsafe.As<Vector256<ulong>, ulong>(ref w), j);
                do
                {
                    Round(a, b, c, ref d, e, f, g, ref h, w0);
                    w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)32);
                    Round(h, a, b, ref c, d, e, f, ref g, w0);
                    w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)32);
                    Round(g, h, a, ref b, c, d, e, ref f, w0);
                    w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)32);
                    Round(f, g, h, ref a, b, c, d, ref e, w0);
                    w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)32);
                    Round(e, f, g, ref h, a, b, c, ref d, w0);
                    w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)32);
                    Round(d, e, f, ref g, h, a, b, ref c, w0);
                    w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)32);
                    Round(c, d, e, ref f, g, h, a, ref b, w0);
                    w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)32);
                    Round(b, c, d, ref e, f, g, h, ref a, w0);
                    w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)32);
                }
                while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

                state += a;
                Unsafe.AddByteOffset(ref state, (IntPtr)8) += b;
                Unsafe.AddByteOffset(ref state, (IntPtr)16) += c;
                Unsafe.AddByteOffset(ref state, (IntPtr)24) += d;
                Unsafe.AddByteOffset(ref state, (IntPtr)32) += e;
                Unsafe.AddByteOffset(ref state, (IntPtr)40) += f;
                Unsafe.AddByteOffset(ref state, (IntPtr)48) += g;
                Unsafe.AddByteOffset(ref state, (IntPtr)56) += h;
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
                Unsafe.WriteUnaligned(ref wRef, Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref currentBlock), _littleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)32), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)32)), _littleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)64), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)64)), _littleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)96), Avx2.Shuffle(Unsafe.As<byte, Vector256<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)96)), _littleEndianMask256));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref wRef, Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref currentBlock), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)16), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)16)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)32), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)32)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)48), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)48)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)64), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)64)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)80), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)80)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)96), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)96)), _littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref wRef, (IntPtr)112), Ssse3.Shuffle(Unsafe.As<byte, Vector128<byte>>(ref Unsafe.AddByteOffset(ref currentBlock, (IntPtr)112)), _littleEndianMask128));
            }
            else
#endif
            {
                unsafe
                {
                    for (IntPtr i = (IntPtr)0; (byte*)i < (byte*)128; i += 8)
                    {
                        Unsafe.AddByteOffset(ref w, i) = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref currentBlock, i)));
                    }
                }
            }

            ref ulong wEnd = ref Unsafe.AddByteOffset(ref w, (IntPtr)(80*8));
            ref ulong w0 = ref Unsafe.AddByteOffset(ref w, (IntPtr)(16*8));
            do
            {
                w0 = Unsafe.SubtractByteOffset(ref w0, (IntPtr)(16*8)) + Sigma0(Unsafe.SubtractByteOffset(ref w0, (IntPtr)(15*8))) + Unsafe.SubtractByteOffset(ref w0, (IntPtr)(7*8)) + Sigma1(Unsafe.SubtractByteOffset(ref w0, (IntPtr)(2*8)));
                Unsafe.AddByteOffset(ref w0, (IntPtr)(1*8)) = Unsafe.SubtractByteOffset(ref w0, (IntPtr)(15*8)) + Sigma0(Unsafe.SubtractByteOffset(ref w0, (IntPtr)(14*8))) + Unsafe.SubtractByteOffset(ref w0, (IntPtr)(6*8)) + Sigma1(Unsafe.SubtractByteOffset(ref w0, (IntPtr)(1*8)));
                w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)(2*8));
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            ulong a = state;
            ulong b = Unsafe.AddByteOffset(ref state, (IntPtr)8);
            ulong c = Unsafe.AddByteOffset(ref state, (IntPtr)16);
            ulong d = Unsafe.AddByteOffset(ref state, (IntPtr)24);
            ulong e = Unsafe.AddByteOffset(ref state, (IntPtr)32);
            ulong f = Unsafe.AddByteOffset(ref state, (IntPtr)40);
            ulong g = Unsafe.AddByteOffset(ref state, (IntPtr)48);
            ulong h = Unsafe.AddByteOffset(ref state, (IntPtr)56);
            w0 = ref w;
            ref ulong k0 = ref _k[0];
            do
            {
                Round(a, b, c, ref d, e, f, g, ref h, w0, k0);
                w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)8);
                k0 = ref Unsafe.AddByteOffset(ref k0, (IntPtr)8);
                Round(h, a, b, ref c, d, e, f, ref g, w0, k0);
                w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)8);
                k0 = ref Unsafe.AddByteOffset(ref k0, (IntPtr)8);
                Round(g, h, a, ref b, c, d, e, ref f, w0, k0);
                w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)8);
                k0 = ref Unsafe.AddByteOffset(ref k0, (IntPtr)8);
                Round(f, g, h, ref a, b, c, d, ref e, w0, k0);
                w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)8);
                k0 = ref Unsafe.AddByteOffset(ref k0, (IntPtr)8);
                Round(e, f, g, ref h, a, b, c, ref d, w0, k0);
                w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)8);
                k0 = ref Unsafe.AddByteOffset(ref k0, (IntPtr)8);
                Round(d, e, f, ref g, h, a, b, ref c, w0, k0);
                w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)8);
                k0 = ref Unsafe.AddByteOffset(ref k0, (IntPtr)8);
                Round(c, d, e, ref f, g, h, a, ref b, w0, k0);
                w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)8);
                k0 = ref Unsafe.AddByteOffset(ref k0, (IntPtr)8);
                Round(b, c, d, ref e, f, g, h, ref a, w0, k0);
                w0 = ref Unsafe.AddByteOffset(ref w0, (IntPtr)8);
                k0 = ref Unsafe.AddByteOffset(ref k0, (IntPtr)8);
            }
            while (Unsafe.IsAddressLessThan(ref w0, ref wEnd));

            state += a;
            Unsafe.AddByteOffset(ref state, (IntPtr)8) += b;
            Unsafe.AddByteOffset(ref state, (IntPtr)16) += c;
            Unsafe.AddByteOffset(ref state, (IntPtr)24) += d;
            Unsafe.AddByteOffset(ref state, (IntPtr)32) += e;
            Unsafe.AddByteOffset(ref state, (IntPtr)40) += f;
            Unsafe.AddByteOffset(ref state, (IntPtr)48) += g;
            Unsafe.AddByteOffset(ref state, (IntPtr)56) += h;
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

        private static readonly ulong[] _k = {
                0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
            };

#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> K256(IntPtr i)
            => Unsafe.AddByteOffset(ref _k256[0], i);

        private static readonly Vector256<ulong>[] _k256 = {
                Vector256.Create(0x428a2f98d728ae22ul), Vector256.Create(0x7137449123ef65cdul), Vector256.Create(0xb5c0fbcfec4d3b2ful), Vector256.Create(0xe9b5dba58189dbbcul),
                Vector256.Create(0x3956c25bf348b538ul), Vector256.Create(0x59f111f1b605d019ul), Vector256.Create(0x923f82a4af194f9bul), Vector256.Create(0xab1c5ed5da6d8118ul),
                Vector256.Create(0xd807aa98a3030242ul), Vector256.Create(0x12835b0145706fbeul), Vector256.Create(0x243185be4ee4b28cul), Vector256.Create(0x550c7dc3d5ffb4e2ul),
                Vector256.Create(0x72be5d74f27b896ful), Vector256.Create(0x80deb1fe3b1696b1ul), Vector256.Create(0x9bdc06a725c71235ul), Vector256.Create(0xc19bf174cf692694ul),
                Vector256.Create(0xe49b69c19ef14ad2ul), Vector256.Create(0xefbe4786384f25e3ul), Vector256.Create(0x0fc19dc68b8cd5b5ul), Vector256.Create(0x240ca1cc77ac9c65ul),
                Vector256.Create(0x2de92c6f592b0275ul), Vector256.Create(0x4a7484aa6ea6e483ul), Vector256.Create(0x5cb0a9dcbd41fbd4ul), Vector256.Create(0x76f988da831153b5ul),
                Vector256.Create(0x983e5152ee66dfabul), Vector256.Create(0xa831c66d2db43210ul), Vector256.Create(0xb00327c898fb213ful), Vector256.Create(0xbf597fc7beef0ee4ul),
                Vector256.Create(0xc6e00bf33da88fc2ul), Vector256.Create(0xd5a79147930aa725ul), Vector256.Create(0x06ca6351e003826ful), Vector256.Create(0x142929670a0e6e70ul),
                Vector256.Create(0x27b70a8546d22ffcul), Vector256.Create(0x2e1b21385c26c926ul), Vector256.Create(0x4d2c6dfc5ac42aedul), Vector256.Create(0x53380d139d95b3dful),
                Vector256.Create(0x650a73548baf63deul), Vector256.Create(0x766a0abb3c77b2a8ul), Vector256.Create(0x81c2c92e47edaee6ul), Vector256.Create(0x92722c851482353bul),
                Vector256.Create(0xa2bfe8a14cf10364ul), Vector256.Create(0xa81a664bbc423001ul), Vector256.Create(0xc24b8b70d0f89791ul), Vector256.Create(0xc76c51a30654be30ul),
                Vector256.Create(0xd192e819d6ef5218ul), Vector256.Create(0xd69906245565a910ul), Vector256.Create(0xf40e35855771202aul), Vector256.Create(0x106aa07032bbd1b8ul),
                Vector256.Create(0x19a4c116b8d2d0c8ul), Vector256.Create(0x1e376c085141ab53ul), Vector256.Create(0x2748774cdf8eeb99ul), Vector256.Create(0x34b0bcb5e19b48a8ul),
                Vector256.Create(0x391c0cb3c5c95a63ul), Vector256.Create(0x4ed8aa4ae3418acbul), Vector256.Create(0x5b9cca4f7763e373ul), Vector256.Create(0x682e6ff3d6b2b8a3ul),
                Vector256.Create(0x748f82ee5defb2fcul), Vector256.Create(0x78a5636f43172f60ul), Vector256.Create(0x84c87814a1f0ab72ul), Vector256.Create(0x8cc702081a6439ecul),
                Vector256.Create(0x90befffa23631e28ul), Vector256.Create(0xa4506cebde82bde9ul), Vector256.Create(0xbef9a3f7b2c67915ul), Vector256.Create(0xc67178f2e372532bul),
                Vector256.Create(0xca273eceea26619cul), Vector256.Create(0xd186b8c721c0c207ul), Vector256.Create(0xeada7dd6cde0eb1eul), Vector256.Create(0xf57d4f7fee6ed178ul),
                Vector256.Create(0x06f067aa72176fbaul), Vector256.Create(0x0a637dc5a2c898a6ul), Vector256.Create(0x113f9804bef90daeul), Vector256.Create(0x1b710b35131c471bul),
                Vector256.Create(0x28db77f523047d84ul), Vector256.Create(0x32caab7b40c72493ul), Vector256.Create(0x3c9ebe0a15c9bebcul), Vector256.Create(0x431d67c49c100d4cul),
                Vector256.Create(0x4cc5d4becb3e42b6ul), Vector256.Create(0x597f299cfc657e2aul), Vector256.Create(0x5fcb6fab3ad6faecul), Vector256.Create(0x6c44198c4a475817ul)
        };

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12,
        // 19, 18, 17, 16, 23, 22, 21, 20,
        // 27, 26, 25, 24, 31, 30, 29, 28
        internal static readonly Vector256<byte> _littleEndianMask256 = Vector256.Create(
                    283686952306183,
                    579005069656919567,
                    1157726452361532951,
                    1736447835066146335
                ).AsByte();

        // 3, 2, 1, 0, 7, 6, 5, 4,
        // 11, 10, 9, 8, 15, 14, 13, 12
        internal static readonly Vector128<byte> _littleEndianMask128 = Vector128.Create(
                    283686952306183,
                    579005069656919567
                ).AsByte();
#endif
    }
}