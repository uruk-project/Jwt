﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken.Cryptography
{
    /// <summary>Provides encryption.</summary>
    internal abstract class AesBlockEncryptor : IDisposable
    {
        /// <summary>The size of the AES block.</summary>
        protected const int BlockSize = 16;

        /// <summary>Encrypt a <paramref name="plaintext"/>.</summary>
        public abstract void EncryptBlock(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext);

        /// <inheritdoc />
        public abstract void Dispose();

        /// <summary>Returns the required ciphertext length.</summary>
        protected static int GetCiphertextLength(int plaintextLength)
            => (plaintextLength + BlockSize) & ~(BlockSize - 1);
    }
}
