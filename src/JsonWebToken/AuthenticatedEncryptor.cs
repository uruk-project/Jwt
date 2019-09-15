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
        /// <summary>
        /// Defines a <see cref="AuthenticatedEncryptor"/> that do nothing.
        /// </summary>
        public static readonly AuthenticatedEncryptor Empty = new EmptyAuthenticatedEncryptor();

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticatedEncryptor"/> class.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptionAlgorithm"></param>
        protected AuthenticatedEncryptor(Jwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            Key = key!; // ! => [DoesNotReturn]
            EncryptionAlgorithm = encryptionAlgorithm!; // ! => [DoesNotReturn]
        }

        /// <summary>
        /// Gets the key.
        /// </summary>
        public Jwk Key { get; }

        /// <summary>
        /// Gets the encryption algorithm.
        /// </summary>
        public EncryptionAlgorithm EncryptionAlgorithm { get; }

        /// <inheritdoc />
        public abstract void Dispose();

        /// <summary>
        /// Encrypts the <paramref name="plaintext"/>.
        /// </summary>
        /// <param name="plaintext">The plaintext to encrypt.</param>
        /// <param name="nonce">An arbitrary value to be used only once.</param>
        /// <param name="associatedData">The associated data.</param>
        /// <param name="ciphertext">The resulting ciphertext.</param>
        /// <param name="authenticationTag">The resulting authentication tag.</param>
        public abstract void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag);

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

        /// <summary>
        /// Try to decrypt the <paramref name="ciphertext"/>. 
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="associatedData">The associated data used to encrypt.</param>
        /// <param name="nonce">The nonce used to encrypt.</param>
        /// <param name="authenticationTag">The authentication tag</param>
        /// <param name="plaintext">The resulting plaintext.</param>
        /// <param name="bytesWritten">The bytes written in the <paramref name="plaintext"/>.</param>
        /// <returns></returns>
        public abstract bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten);

        internal class EmptyAuthenticatedEncryptor : AuthenticatedEncryptor
        {
            public EmptyAuthenticatedEncryptor() 
                : base(Jwk.Empty, EncryptionAlgorithm.Empty)
            {
            }

            public override void Dispose()
            {
            }

            public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag)
            {
            }

            public override int GetBase64NonceSize() => 0;

            public override int GetBase64TagSize() => 0;

            public override int GetCiphertextSize(int plaintextSize) => 0;

            public override int GetNonceSize() => 0;

            public override int GetTagSize() => 0;

            public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
            {
                bytesWritten = 0;
                return true;
            }
        }
    }
}