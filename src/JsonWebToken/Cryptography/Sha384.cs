﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Buffers.Binary;
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
    public class Sha384 : Sha2
    {
        private const int Sha384HashSize = 48;
        private const int Sha384BlockSize = 128;

        /// <summary>
        /// Gets the default instance of the <see cref="Sha384"/> class.
        /// </summary>
        public static readonly Sha384 Shared = new Sha384();

        /// <inheritsdoc />
        public override int HashSize => Sha384HashSize;

        /// <inheritsdoc />
        public override int BlockSize => Sha384BlockSize;

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend, Span<uint> w)
        {
            throw new NotImplementedException();
        }

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> prepend, Span<ulong> w)
        {
            if (destination.Length < Sha384HashSize)
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, Sha384HashSize);
            }

            // init
            Span<ulong> state = stackalloc ulong[] {
                0xcbbb9d5dc1059ed8ul,
                0x629a292a367cd507ul,
                0x9159015a3070dd17ul,
                0x152fecd8f70e5939ul,
                0x67332667ffc00b31ul,
                0x8eb44a8768581511ul,
                0xdb0c2e0d64f98fa7ul,
                0x47b5481dbefa4fa4ul
            };
            int dataLength = source.Length + prepend.Length;
            int remaining = dataLength & (Sha384BlockSize - 1);
            Span<byte> lastBlock = stackalloc byte[Sha384BlockSize];
            ref byte lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

            // update
            Span<ulong> wTemp = w.IsEmpty ? stackalloc ulong[80] : w;
            ref ulong wRef = ref MemoryMarshal.GetReference(wTemp);
            ref ulong stateRef = ref MemoryMarshal.GetReference(state);
            ref byte srcStartRef = ref MemoryMarshal.GetReference(source);
            ref byte srcRef = ref srcStartRef;
            if (!prepend.IsEmpty)
            {
                if (prepend.Length == Sha384BlockSize)
                {
                    Sha512.Transform(ref stateRef, ref MemoryMarshal.GetReference(prepend), ref wRef);
                }
                else if (prepend.Length < Sha384BlockSize)
                {
                    Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref MemoryMarshal.GetReference(prepend), (uint)prepend.Length);
                    int srcRemained = Sha384BlockSize - prepend.Length;
                    if (dataLength >= Sha384BlockSize)
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)srcRemained);
                        Sha512.Transform(ref stateRef, ref lastBlockRef, ref wRef);
                        srcRef = ref Unsafe.AddByteOffset(ref srcRef, (IntPtr)srcRemained);
                    }
                    else
                    {
                        Unsafe.CopyBlockUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)prepend.Length), ref srcRef, (uint)source.Length);
                        goto Final;
                    }
                }
                else
                {
                    ThrowHelper.ThrowArgumentException_PrependMustBeLessOrEqualToBlockSize(prepend, Sha384BlockSize);
                }
            }

            ref byte srcEndRef = ref Unsafe.AddByteOffset(ref srcStartRef, (IntPtr)(source.Length - Sha384BlockSize + 1));
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            if (Avx2.IsSupported)
            {
                ref byte srcSimdEndRef = ref Unsafe.AddByteOffset(ref srcStartRef, (IntPtr)(source.Length - 4 * Sha384BlockSize + 1));
                if (Unsafe.IsAddressLessThan(ref srcRef, ref srcSimdEndRef))
                {
                    Vector256<ulong>[] returnToPool;
                    Span<Vector256<ulong>> w4 = returnToPool = ArrayPool<Vector256<ulong>>.Shared.Rent(80);
                    try
                    {
                        ref Vector256<ulong> w4Ref = ref MemoryMarshal.GetReference(w4);
                        do
                        {
                            Sha512.Transform(ref stateRef, ref srcRef, ref w4Ref);
                            srcRef = ref Unsafe.AddByteOffset(ref srcRef, (IntPtr)(Sha384BlockSize * 4));
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
                Sha512.Transform(ref stateRef, ref srcRef, ref wRef);
                srcRef = ref Unsafe.AddByteOffset(ref srcRef, (IntPtr)Sha384BlockSize);
            }

            // final
            Unsafe.CopyBlockUnaligned(ref lastBlockRef, ref srcRef, (uint)remaining);

        Final:
            // Pad the last block
            Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)remaining) = 0x80;
            lastBlock.Slice(remaining + 1).Clear();
            if (remaining >= Sha384BlockSize - 2 * sizeof(ulong))
            {
                Sha512.Transform(ref stateRef, ref lastBlockRef, ref wRef);
                lastBlock.Slice(0, Sha384BlockSize - 2 * sizeof(ulong)).Clear();
            }

            // Append to the padding the total message's length in bits and transform.
            ulong bitLength = (ulong)dataLength << 3;
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)(Sha384BlockSize - 16)), 0ul); // Don't support input length > 2^64
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref lastBlockRef, (IntPtr)(Sha384BlockSize - 8)), BinaryPrimitives.ReverseEndianness(bitLength));
            Sha512.Transform(ref stateRef, ref lastBlockRef, ref wRef);

            // reverse all the bytes when copying the final state to the output hash.
            ref byte destinationRef = ref MemoryMarshal.GetReference(destination);
#if !NETSTANDARD2_0 && !NET461 && !NETCOREAPP2_1
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Avx2.Shuffle(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.As<ulong, byte>(ref stateRef)), Sha512._littleEndianMask256));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)32), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref Unsafe.As<ulong, byte>(ref stateRef), (IntPtr)32)), Sha512._littleEndianMask128));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.As<ulong, byte>(ref stateRef)), Sha512._littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)16), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref Unsafe.As<ulong, byte>(ref stateRef), (IntPtr)16)), Sha512._littleEndianMask128));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)32), Ssse3.Shuffle(Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref Unsafe.As<ulong, byte>(ref stateRef), (IntPtr)32)), Sha512._littleEndianMask128));
            }
            else
#endif
            {
                Unsafe.WriteUnaligned(ref destinationRef, BinaryPrimitives.ReverseEndianness(stateRef));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)8), BinaryPrimitives.ReverseEndianness( Unsafe.AddByteOffset(ref stateRef, (IntPtr)8)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)16), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)16)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)24), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)24)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)32), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)32)));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)40), BinaryPrimitives.ReverseEndianness(Unsafe.AddByteOffset(ref stateRef, (IntPtr)40)));
            }
        }
    }
}