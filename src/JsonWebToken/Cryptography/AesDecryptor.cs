﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if SUPPORT_SIMD
using System.Runtime.Intrinsics;
#endif

namespace JsonWebToken.Cryptography
{

    /// <summary>
    /// Provides AES decryption.
    /// </summary>
    internal abstract class AesDecryptor
    {
        /// <summary>
        /// The size of the AES block.
        /// </summary>
        protected const int BlockSize = 16;

        /// <summary>
        /// Try to decrypt the <paramref name="ciphertext"/>. 
        /// </summary>
        /// <param name="key">The decryption key.</param>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="nonce">The nonce used to encrypt.</param>
        /// <param name="plaintext">The resulting plaintext.</param>
        /// <param name="bytesWritten">The bytes written in the <paramref name="plaintext"/>.</param>
        /// <returns></returns>
        public abstract bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten);

#if SUPPORT_SIMD
        /// <summary>
        /// Gets the padding mask used to validate the padding of the ciphertext. The padding value MUST be between 0 and 16 included.
        /// </summary>
        /// <param name="padding"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static Vector128<byte> GetPaddingMask(byte padding)
        {
            ref Vector128<byte> tmp = ref Unsafe.As<byte, Vector128<byte>>(ref MemoryMarshal.GetReference(PaddingMask));
            return Unsafe.Add(ref tmp, (IntPtr)padding);
        }

        private static ReadOnlySpan<byte> PaddingMask => new byte[17 * 16]
        {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x02,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x03,0x03,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x04,0x04,0x04,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,0x05,0x05,0x05,0x05,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x06,0x06,0x06,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x07,0x07,0x07,0x07,0x07,0x07,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09,0x09,0x09,0x09,0x09,0x09,0x09,0x09,0x09,
            0x00,0x00,0x00,0x00,0x00,0x00,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,0x0A,
            0x00,0x00,0x00,0x00,0x00,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,
            0x00,0x00,0x00,0x00,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,
            0x00,0x00,0x00,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,0x0D,
            0x00,0x00,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,0x0E,
            0x00,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,0x0F,
            0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10
        };
#endif
    }
}
