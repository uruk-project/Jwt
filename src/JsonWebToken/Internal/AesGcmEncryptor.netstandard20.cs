// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.
#if !NETCOREAPP3_0
using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption and decryption for AES GCM algorithm.
    /// </summary>
    internal sealed class AesGcmEncryptor : AuthenticatedEncryptor
    {
        public AesGcmEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
            : base(key, encryptionAlgorithm)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetCiphertextSize(int plaintextSize)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetNonceSize()
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetBase64NonceSize()
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetTagSize()
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetBase64TagSize()
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override void Dispose()
        {
        }
    }
}
#endif