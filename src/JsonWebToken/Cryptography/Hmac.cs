// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;

namespace JsonWebToken.Cryptography
{
    internal readonly ref struct Hmac
    {
        /// <summary>The hash algorithm.</summary>
        public Sha2 Sha2 { get; }

        /// <summary>The inner &amp; outer pad keys.</summary>
        private readonly Span<byte> _keys;

        /// <summary>The block size.</summary>
        public int BlockSize => Sha2.BlockSize;

        /// <summary>The size of the resulting hash.</summary>
        public int HashSize => Sha2.HashSize;

        /// <summary>Initializes a new instance of the <see cref="HmacSha2"/> class.</summary>
        public Hmac(Sha2 sha2, ReadOnlySpan<byte> key, Span<byte> hmacKey)
        {
            Debug.Assert(sha2 != null);
            Debug.Assert(hmacKey.Length == sha2!.BlockSize * 2);

            Sha2 = sha2;
            _keys = hmacKey;
            int blockSize = sha2.BlockSize;
            if (key.Length > blockSize)
            {
                Span<byte> keyPrime = stackalloc byte[blockSize];
                HmacHelper.InitializeIOKeys(keyPrime, _keys, blockSize);
                keyPrime.Clear();
            }
            else
            {
                HmacHelper.InitializeIOKeys(key, _keys, blockSize);
            }
        }

        /// <summary>Computes the hash value.</summary>
        public void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            // hash(o_key_pad ∥ hash(i_key_pad ∥ message));         
            int size = Sha2.GetWorkingSetSize(source.Length);
            int blockSize = Sha2.BlockSize;
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> W = size > Constants.MaxStackallocBytes
                    ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(size))
                    : stackalloc byte[size];
                Sha2.ComputeHash(source, _keys.Slice(0, blockSize), destination, W);
                Sha2.ComputeHash(destination, _keys.Slice(blockSize, blockSize), destination, W);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        /// <summary>Computes the hash value.</summary>
        public void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination, Span<byte> W)
        {
            // hash(o_key_pad ∥ hash(i_key_pad ∥ message));         
            int blockSize = Sha2.BlockSize;
            Sha2.ComputeHash(source, _keys.Slice(0, blockSize), destination, W);
            Sha2.ComputeHash(destination, _keys.Slice(blockSize, blockSize), destination, W);
        }
    }
}
