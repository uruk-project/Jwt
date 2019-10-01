// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides AES decryption.
    /// </summary>
    public abstract class AesDecryptor : IDisposable
    {
        /// <summary>
        /// Try to decrypt the <paramref name="ciphertext"/>. 
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="nonce">The nonce used to encrypt.</param>
        /// <param name="plaintext">The resulting plaintext.</param>
        /// <param name="bytesWritten">The bytes written in the <paramref name="plaintext"/>.</param>
        /// <returns></returns>
        public abstract bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten);

        /// <inheritdoc />
        public abstract void Dispose();
    }
}