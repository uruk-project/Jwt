﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
#if SUPPORT_SIMD
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Provides AES decryption.
    /// </summary>
    public abstract class AesBlockDecryptor : IDisposable
    {
        /// <summary>
        /// The size of the AES block.
        /// </summary>
        protected const int BlockSize = 16;

        /// <inheritdoc />
        public abstract void Dispose();

        /// <summary>
        /// Decrypt a <paramref name="ciphertext"/>.
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <param name="plaintext"></param>
        public abstract void DecryptBlock(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext);
    }
}
