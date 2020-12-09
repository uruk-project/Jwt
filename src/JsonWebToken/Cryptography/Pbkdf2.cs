// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;

namespace JsonWebToken.Cryptography
{
    // PBKDF2 is defined in NIST SP800-132, Sec. 5.3.
    // http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
    internal static class Pbkdf2
    {
        public static void DeriveKey(byte[] password, ReadOnlySpan<byte> salt, Sha2 prf, uint iterationCount, Span<byte> destination)
        {
            Debug.Assert(password != null);
            Debug.Assert(salt != null);
            Debug.Assert(destination.Length > 0);

            int numBytesWritten = 0;
            int numBytesRemaining = destination.Length;

            Span<byte> saltWithBlockIndex = stackalloc byte[checked(salt.Length + sizeof(uint))];
            salt.CopyTo(saltWithBlockIndex);

            Span<byte> hmacKey = stackalloc byte[prf.BlockSize * 2];
            var hashAlgorithm = new Hmac(prf, password, hmacKey);

            int wSize = prf.GetWorkingSetSize(int.MaxValue);
            int blockSize = hashAlgorithm.BlockSize;
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> W = wSize > Constants.MaxStackallocBytes
                    ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(wSize))
                    : stackalloc byte[wSize];
                Span<byte> currentBlock = stackalloc byte[hashAlgorithm.HashSize];
                Span<byte> iterationBlock = stackalloc byte[hashAlgorithm.HashSize];
                Span<byte> blockIndexDestination = saltWithBlockIndex.Slice(saltWithBlockIndex.Length - sizeof(uint));
                for (uint blockIndex = 1; numBytesRemaining > 0; blockIndex++)
                {
                    BinaryPrimitives.WriteUInt32BigEndian(blockIndexDestination, blockIndex);
                    hashAlgorithm.ComputeHash(saltWithBlockIndex, currentBlock, W); // U_1
                    currentBlock.CopyTo(iterationBlock);
                    for (int iter = 1; iter < iterationCount; iter++)
                    {
                        hashAlgorithm.ComputeHash(currentBlock, currentBlock, W);
                        Xor(src: currentBlock, dest: iterationBlock);
                    }

                    int numBytesToCopy = Math.Min(numBytesRemaining, iterationBlock.Length);
                    iterationBlock.Slice(0, numBytesToCopy).CopyTo(destination.Slice(numBytesWritten));
                    numBytesWritten += numBytesToCopy;
                    numBytesRemaining -= numBytesToCopy;
                }
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        private static unsafe void Xor(Span<byte> src, Span<byte> dest)
        {
            fixed (byte* srcPtr = &MemoryMarshal.GetReference(src))
            fixed (byte* destPtr = &MemoryMarshal.GetReference(dest))
            {
                byte* srcCurrent = srcPtr;
                byte* destCurrent = destPtr;
                byte* srcEnd = srcPtr + src.Length;

                if (srcEnd - srcCurrent >= sizeof(int))
                {
                    // align to sizeof(int)
                    while (((ulong)srcCurrent & (sizeof(int) - 1)) != 0)
                    {
                        *destCurrent++ ^= *srcCurrent++;
                    }

                    if (Vector.IsHardwareAccelerated && ((Vector<byte>.Count & (sizeof(int) - 1)) == 0) && (srcEnd - srcCurrent) >= Vector<byte>.Count)
                    {
                        // align to Vector<byte>.Count
                        while ((ulong)srcCurrent % (uint)Vector<byte>.Count != 0)
                        {
                            Debug.Assert(srcCurrent < srcEnd);

                            *(int*)destCurrent ^= *(int*)srcCurrent;
                            srcCurrent += sizeof(int);
                            destCurrent += sizeof(int);
                        }

                        if (srcEnd - srcCurrent >= Vector<byte>.Count)
                        {
                            do
                            {
                                *(Vector<byte>*)destCurrent ^= *(Vector<byte>*)srcCurrent;
                                srcCurrent += Vector<byte>.Count;
                                destCurrent += Vector<byte>.Count;
                            }
                            while (srcEnd - srcCurrent >= Vector<byte>.Count);
                        }
                    }

                    // process remaining data (or all, if couldn't use SIMD) 4 bytes at a time.
                    while (srcEnd - srcCurrent >= sizeof(int))
                    {
                        *(int*)destCurrent ^= *(int*)srcCurrent;
                        srcCurrent += sizeof(int);
                        destCurrent += sizeof(int);
                    }
                }

                // do any remaining data a byte at a time.
                while (srcCurrent != srcEnd)
                {
                    *destCurrent++ ^= *srcCurrent++;
                }
            }
        }
    }
}
