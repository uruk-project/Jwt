// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken.Cryptography
{
    /// <summary>Provides authenticated decryption.</summary>
    public abstract class AuthenticatedDecryptor
    {
        /// <summary>Try to decrypt the <paramref name="ciphertext"/>.</summary>
        /// <param name="key">The encyrption key.</param>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="associatedData">The associated data used to encrypt.</param>
        /// <param name="nonce">The nonce used to encrypt.</param>
        /// <param name="authenticationTag">The authentication tag</param>
        /// <param name="plaintext">The resulting plaintext.</param>
        /// <param name="bytesWritten">The bytes written in the <paramref name="plaintext"/>.</param>
        /// <returns></returns>
        public abstract bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten);

        /// <summary>Gets the size of the authentication tag.</summary>
        public abstract int GetTagSize();
    }
}