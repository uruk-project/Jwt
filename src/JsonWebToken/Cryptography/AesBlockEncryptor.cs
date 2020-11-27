// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides encryption.
    /// </summary>
    public abstract class AesBlockEncryptor : IDisposable
    {
        /// <summary>
        /// The size of the AES block.
        /// </summary>
        protected const int BlockSize = 16;

        /// <summary>
        /// Encrypt a <paramref name="plaintext"/>.
        /// </summary>
        /// <param name="plaintext"></param>
        /// <param name="ciphertext"></param>
        public abstract void EncryptBlock(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext);

        /// <inheritdoc />
        public abstract void Dispose();

        /// <summary>
        /// Returns the required ciphertext length.
        /// </summary>
        /// <param name="plaintextLength"></param>
        protected static int GetCiphertextLength(int plaintextLength)
            => (plaintextLength + BlockSize) & ~(BlockSize - 1);
    }
}