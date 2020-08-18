// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
#if SUPPORT_SIMD
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) using a SHA2 hash function.
    /// </summary>
    public abstract class HmacSha2
    {
        /// <summary>
        /// The hash algorithm.
        /// </summary>
        public Sha2 Sha2 { get; }

        /// <summary>
        /// The inner &amp; outer pad keys.
        /// </summary>
        protected readonly byte[] _keys;

        /// <summary>
        /// The inner pad key.
        /// </summary>
        protected ReadOnlyMemory<byte> _innerPadKey;

        /// <summary>
        /// The outer pad key.
        /// </summary>
        protected ReadOnlyMemory<byte> _outerPadKey;

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
        protected HmacSha2(Sha2 sha2, ReadOnlySpan<byte> key)
        {
            if (sha2 is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.sha);
            }

            Sha2 = sha2;
            _keys = new byte[BlockSize * 2];
            _innerPadKey = new ReadOnlyMemory<byte>(_keys, 0, BlockSize);
            _outerPadKey = new ReadOnlyMemory<byte>(_keys, BlockSize, BlockSize);
            if (key.Length > BlockSize)
            {
                Span<byte> keyPrime = stackalloc byte[sha2.HashSize];
                Sha2.ComputeHash(key, default, keyPrime, default);
                InitializeIOKeys(keyPrime);
                keyPrime.Clear();
            }
            else
            {
                InitializeIOKeys(key);
            }
        }

        private void InitializeIOKeys(ReadOnlySpan<byte> key)
        {
#if SUPPORT_SIMD
            if (Avx2.IsSupported && key.Length != 0 && (key.Length & 31) == 0)
            {
                Vector256<byte> innerKeyInit = Vector256.Create((byte)0x36);
                Vector256<byte> outerKeyInit = Vector256.Create((byte)0x5c);
                ref byte keyRef = ref MemoryMarshal.GetReference(key);
                ref byte keyEndRef = ref Unsafe.Add(ref keyRef, key.Length);
                ref byte innerKeyRef = ref Unsafe.AsRef(_keys[0]);
                ref byte outerKeyRef = ref Unsafe.Add(ref innerKeyRef, BlockSize);
                ref byte innerKeyEndRef = ref outerKeyRef;
                do
                {
                    var k1 = Unsafe.ReadUnaligned<Vector256<byte>>(ref keyRef);
                    Unsafe.WriteUnaligned(ref innerKeyRef, Avx2.Xor(k1, innerKeyInit));
                    Unsafe.WriteUnaligned(ref outerKeyRef, Avx2.Xor(k1, outerKeyInit));

                    // assume the IO keys are Modulo 32
                    keyRef = ref Unsafe.Add(ref keyRef, 32);
                    innerKeyRef = ref Unsafe.Add(ref innerKeyRef, 32);
                    outerKeyRef = ref Unsafe.Add(ref outerKeyRef, 32);
                } while (Unsafe.IsAddressLessThan(ref keyRef, ref keyEndRef));

                // treat the remain
                while (Unsafe.IsAddressLessThan(ref innerKeyRef, ref innerKeyEndRef))
                {
                    Unsafe.WriteUnaligned(ref innerKeyRef, innerKeyInit);
                    Unsafe.WriteUnaligned(ref outerKeyRef, outerKeyInit);
                    innerKeyRef = ref Unsafe.Add(ref innerKeyRef, 32);
                    outerKeyRef = ref Unsafe.Add(ref outerKeyRef, 32);
                }
            }
            else
#endif
            {
                int i = 0;
                while (i < key.Length)
                {
                    _keys[i] = (byte)(key[i] ^ 0x36);
                    _keys[i + BlockSize] = (byte)(key[i] ^ 0x5c);
                    i++;
                }

                while (i < BlockSize)
                {
                    _keys[i] ^= 0x36;
                    _keys[i + BlockSize] ^= 0x5c;
                    i++;
                }
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
    }
}
