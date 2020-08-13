// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if !SUPPORT_AESGCM
using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption for AES GCM algorithm.
    /// </summary>
    internal sealed class AesGcmEncryptor : AuthenticatedEncryptor
    {
        public AesGcmEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
        }

        /// <inheritdoc />
        public override void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag, out int authenticationTagBytesWritten)
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
    }
}
#endif