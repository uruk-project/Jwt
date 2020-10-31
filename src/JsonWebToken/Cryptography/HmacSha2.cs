// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;

namespace JsonWebToken
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) using a SHA2 hash function.
    /// </summary>
    internal sealed class HmacSha2 : IDisposable
    {
        /// <summary>
        /// The hash algorithm.
        /// </summary>
        public Sha2 Sha2 { get; }

        /// <summary>
        /// The inner &amp; outer pad keys.
        /// </summary>
        private readonly byte[] _keys;

        /// <summary>
        /// The inner pad key.
        /// </summary>
        private readonly ReadOnlyMemory<byte> _innerPadKey;

        /// <summary>
        /// The outer pad key.
        /// </summary>
        private readonly ReadOnlyMemory<byte> _outerPadKey;

        /// <summary>
        /// The block size.
        /// </summary>
        public int BlockSize => Sha2.BlockSize;

        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public int HashSize => Sha2.HashSize;

        /// <summary>
        /// Initializes a new instance of the <see cref="HmacSha2"/> class.
        /// </summary>
        /// <param name="sha2"></param>
        /// <param name="key"></param>
        public HmacSha2(Sha2 sha2, ReadOnlySpan<byte> key)
        {
            if (sha2 is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.sha);
            }

            Sha2 = sha2;
            int blockSize = sha2.BlockSize;
            _keys = ArrayPool<byte>.Shared.Rent(blockSize * 2);
            _innerPadKey = new ReadOnlyMemory<byte>(_keys, 0, blockSize);
            _outerPadKey = new ReadOnlyMemory<byte>(_keys, blockSize, blockSize);
            if (key.Length > blockSize)
            {
                Span<byte> keyPrime = stackalloc byte[sha2.HashSize];
                Sha2.ComputeHash(key, default, keyPrime, default);
                HmacHelper.InitializeIOKeys(keyPrime, _keys, blockSize);
                keyPrime.Clear();
            }
            else
            {
                HmacHelper.InitializeIOKeys(key, _keys, blockSize);
            }
        }

        /// <summary>
        /// Computes the hash value.
        /// </summary>
        /// <param name="source"></param>
        /// <param name="destination"></param>
        public void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            // hash(o_key_pad ∥ hash(i_key_pad ∥ message));         
            int size = Sha2.GetWorkingSetSize(source.Length);
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> W = size > Constants.MaxStackallocBytes
                    ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(size))
                    : stackalloc byte[size];
                Sha2.ComputeHash(source, _innerPadKey.Span, destination, W);
                Sha2.ComputeHash(destination, _outerPadKey.Span, destination, W);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        /// <summary>
        /// Clears the keys.
        /// </summary>
        public void Clear()
        {
            _keys.AsSpan().Clear();
        }

        /// <summary>
        /// Clears the non-managed resources.
        /// </summary>
        public void Dispose()
        {
            Clear();
            ArrayPool<byte>.Shared.Return(_keys);
        }
    }
}
