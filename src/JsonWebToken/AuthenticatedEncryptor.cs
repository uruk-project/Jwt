// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides authenticated encryption and decryption.
    /// </summary>
    public abstract class AuthenticatedEncryptor : IDisposable
    {
        public abstract void Dispose();

        public abstract void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> tag);

        public abstract int GetCiphertextSize(int plaintextSize);

        public abstract int GetNonceSize();

        public abstract int GetTagSize();

        public abstract bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten);
    }
}