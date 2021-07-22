// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if SUPPORT_SIMD
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken.Cryptography
{
    /// <summary>Computes SHA2-512 hash values.</summary>
    public sealed class Sha384 : Sha2
    {
        /// <summary>The resulting hash size of the <see cref="Sha384"/> algorithm.</summary>
        public const int Sha384HashSize = 48;

        /// <summary>
        /// The required  block size of the <see cref="Sha384"/> algorithm.
        /// </summary>
        public const int Sha384BlockSize = 128;
        private const int IterationCount = 80;

        /// <summary>Gets the default instance of the <see cref="Sha384"/> class.</summary>
        public static readonly Sha384 Shared = new Sha384();

        /// <inheritsdoc />
        public override int HashSize => Sha384HashSize;

        /// <inheritsdoc />
        public override int BlockSize => Sha384BlockSize;

        /// <inheritsdoc />
        public override int GetWorkingSetSize(int sourceLength)
#if SUPPORT_SIMD
            => Ssse3.IsSupported && sourceLength >= 4 * Sha384BlockSize ? IterationCount * 32 : IterationCount * 8;
#else
            => IterationCount * 8;
#endif

        /// <summary>Computes the hash value for the specified <paramref name="source"/>.</summary>
        /// <param name="source">The data to hash.</param>
        /// <param name="prepend">Optionnal. The data to hash before the source. Must be of the length of <see cref="BlockSize"/> or less.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        /// <param name="workingSet">Optionnal. The working set used for computing the hash. Useful if you expect to chain hashing in the same thread and you want to avoid memory allocations. Use the method <see cref="GetWorkingSetSize(int)"/> for getting the required size. </param>
        public static void Hash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination, Span<byte> workingSet)
            => Shared.ComputeHash(source, prepend, destination, workingSet);

        /// <summary>Computes the hash value for the specified <paramref name="source"/>.</summary>
        /// <param name="source">The data to hash.</param>
        /// <param name="prepend">Optionnal. The data to hash before the source. Must be of the length of <see cref="BlockSize"/> or less.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        public static void Hash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination)
           => Shared.ComputeHash(source, prepend, destination);

        /// <summary>Computes the hash value for the specified <paramref name="source"/>.</summary>
        /// <param name="source">The data to hash.</param>
        /// <param name="destination">The destination <see cref="Span{T}"/>.</param>
        public static void Hash(ReadOnlySpan<byte> source, Span<byte> destination)
            => Shared.ComputeHash(source, destination);

        /// <inheritsdoc />
        public override void ComputeHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination, Span<byte> workingSet)
        {
            if (destination.Length < Sha384HashSize)
            {
                ThrowHelper.ThrowArgumentException_DestinationTooSmall(destination.Length, Sha384HashSize);
            }

            if (source.IsEmpty)
            {
                if (prepend.IsEmpty)
                {
                    EmptyHash.CopyTo(destination);
                }
                else
                {
                    ComputeHash(prepend, default, destination, workingSet);
                }

                return;
            }

            // init
            Span<ulong> state = stackalloc ulong[8];
            Unsafe.CopyBlock(ref MemoryMarshal.GetReference(MemoryMarshal.AsBytes(state)), ref MemoryMarshal.GetReference(InitState), Sha512.Sha512HashSize);

            int dataLength = source.Length + prepend.Length;
            int remaining = dataLength & (Sha384BlockSize - 1);
            Span<byte> lastBlock = stackalloc byte[Sha384BlockSize];
            ref byte lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

            // update
            Span<byte> wTemp = workingSet.Length < IterationCount * sizeof(ulong) 
                                ? stackalloc byte[IterationCount * sizeof(ulong)] 
                                : workingSet;
            ref ulong wRef = ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetReference(wTemp));
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
#if SUPPORT_SIMD
            if (Avx2.IsSupported)
            {
                ref byte srcSimdEndRef = ref Unsafe.AddByteOffset(ref srcStartRef, (IntPtr)(source.Length - 4 * Sha384BlockSize + 1));
                if (Unsafe.IsAddressLessThan(ref srcRef, ref srcSimdEndRef))
                {
                    byte[]? returnToPool = null;
                    Span<byte> w4 = workingSet.Length < IterationCount * 32 ? (returnToPool = ArrayPool<byte>.Shared.Rent(IterationCount * 32)) : workingSet;
                    try
                    {
                        ref Vector256<ulong> w4Ref = ref Unsafe.As<byte, Vector256<ulong>>(ref MemoryMarshal.GetReference(w4));
                        do
                        {
                            Sha512.Transform(ref stateRef, ref srcRef, ref w4Ref);
                            srcRef = ref Unsafe.AddByteOffset(ref srcRef, (IntPtr)(Sha384BlockSize * 4));
                        } while (Unsafe.IsAddressLessThan(ref srcRef, ref srcSimdEndRef));
                    }
                    finally
                    {
                        if (returnToPool != null)
                        {
                            ArrayPool<byte>.Shared.Return(returnToPool);
                        }
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
#if SUPPORT_SIMD
            if (Avx2.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Avx2.Shuffle(Unsafe.As<ulong, Vector256<byte>>(ref stateRef), EndiannessMask256UInt64));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)32), Ssse3.Shuffle(Unsafe.AddByteOffset(ref Unsafe.As<ulong, Vector128<byte>>(ref stateRef), (IntPtr)32), EndiannessMask128UInt64));
            }
            else if (Ssse3.IsSupported)
            {
                Unsafe.WriteUnaligned(ref destinationRef, Ssse3.Shuffle(Unsafe.As<ulong, Vector128<byte>>(ref stateRef), EndiannessMask128UInt64));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)16), Ssse3.Shuffle(Unsafe.AddByteOffset(ref Unsafe.As<ulong, Vector128<byte>>(ref stateRef), (IntPtr)16), EndiannessMask128UInt64));
                Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref destinationRef, (IntPtr)32), Ssse3.Shuffle(Unsafe.AddByteOffset(ref Unsafe.As<ulong, Vector128<byte>>(ref stateRef), (IntPtr)32), EndiannessMask128UInt64));
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
            }
        }

        // 0xcbbb9d5dc1059ed8ul,
        // 0x629a292a367cd507ul,
        // 0x9159015a3070dd17ul,
        // 0x152fecd8f70e5939ul,
        // 0x67332667ffc00b31ul,
        // 0x8eb44a8768581511ul,
        // 0xdb0c2e0d64f98fa7ul,
        // 0x47b5481dbefa4fa4ul
        private static ReadOnlySpan<byte> InitState => new byte[Sha512.Sha512HashSize]
        {
            216, 158, 5, 193, 93, 157, 187, 203,
            7, 213, 124, 54, 42, 41, 154, 98,
            23, 221, 112, 48, 90, 1, 89, 145,
            57, 89, 14, 247, 216, 236, 47, 21,
            49, 11, 192, 255, 103, 38, 51, 103,
            17, 21, 88, 104, 135, 74, 180, 142,
            167, 143, 249, 100, 13, 46, 12, 219,
            164, 79, 250, 190, 29, 72, 181, 71
        };

        private static ReadOnlySpan<byte> EmptyHash => new byte[Sha384HashSize]
        {
            56, 176, 96, 167, 81, 172, 150, 56,
            76, 217, 50, 126, 177, 177, 227, 106,
            33, 253, 183, 17, 20, 190, 7, 67,
            76, 12, 199, 191, 99, 246, 225, 218,
            39, 78, 222, 191, 231, 111, 101, 251,
            213, 26, 210, 241, 72, 152, 185, 91
        };
    }
}