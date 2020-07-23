// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Provides authenticated encryption and decryption.
    /// </summary>
    public abstract class AuthenticatedEncryptor : IDisposable
    {
        /// <summary>
        /// Encrypts the <paramref name="plaintext"/>.
        /// </summary>
        /// <param name="key">The key used to encrypt to encrypt.</param>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <param name="nonce">An arbitrary value to be used only once.</param>
        /// <param name="associatedData">The associated data.</param>
        /// <param name="ciphertext">The resulting ciphertext.</param>
        /// <param name="authenticationTag">The resulting authentication tag.</param>
        /// <param name="authenticationTagBytesWritten">The number of written bytes for the authentication tag.</param>
        public abstract void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag, out int authenticationTagBytesWritten);

        /// <summary>
        /// Gets the size of the resulting ciphertext.
        /// </summary>
        /// <param name="plaintextSize">The plaintext size.</param>
        public abstract int GetCiphertextSize(int plaintextSize);

        /// <summary>
        /// Gets the required size of the nonce.
        /// </summary>
        public abstract int GetNonceSize();

        /// <summary>
        /// Gets the size of the resulting authentication tag.
        /// </summary>
        public abstract int GetTagSize();

        /// <summary>
        /// Gets the required size of the  base64-URL nonce.
        /// </summary>
        public abstract int GetBase64NonceSize();

        /// <summary>
        /// Gets the size of the base64-URL authentication tag.
        /// </summary>
        public abstract int GetBase64TagSize();

        /// <inheritdoc />
        public abstract void Dispose();


        /// <inheritsdoc />
        public static AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {


            ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            return null;
        }
    }
}