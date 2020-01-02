// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides encryption.
    /// </summary>
    public abstract class AesEncryptor : IDisposable
    {
        /// <summary>
        /// Encrypts the <paramref name="plaintext"/>.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <param name="nonce">An arbitrary value to be used only once.</param>
        /// <param name="ciphertext">The resulting ciphertext.</param>
        public abstract void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> ciphertext);

        /// <summary>
        /// Encrypt a <paramref name="plaintext"/>.
        /// </summary>
        /// <param name="plaintext"></param>
        /// <param name="ciphertext"></param>
        public abstract void EncryptBlock(ref byte plaintext, ref byte ciphertext);

        /// <inheritdoc />
        public abstract void Dispose();
    }
}