// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides encryption.
    /// </summary>
    public abstract class AesEncryptor
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
        public abstract void EncryptBlock(ref byte plaintext, ref byte ciphertext);

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