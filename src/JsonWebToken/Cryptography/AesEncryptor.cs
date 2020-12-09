// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
#if SUPPORT_SIMD
#endif

namespace JsonWebToken.Cryptography
{
    /// <summary>
    /// Provides encryption.
    /// </summary>
    internal abstract class AesEncryptor
    {
        /// <summary>
        /// The size of the AES block.
        /// </summary>
        protected const int BlockSize = 16;

        /// <summary>
        /// Encrypts the <paramref name="plaintext"/>.
        /// </summary>
        /// <param name="key">The key used to encrypt.</param>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <param name="nonce">An arbitrary value to be used only once.</param>
        /// <param name="ciphertext">The resulting ciphertext.</param>
        public abstract void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> ciphertext);

        /// <summary>
        /// Returns the required ciphertext length.
        /// </summary>
        /// <param name="plaintextLength"></param>
        protected static int GetCiphertextLength(int plaintextLength)
            => (plaintextLength + BlockSize) & ~(BlockSize - 1);
    }
}
