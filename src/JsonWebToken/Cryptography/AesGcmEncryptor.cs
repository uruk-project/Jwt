﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_AESGCM
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption for AES GCM algorithm.
    /// </summary>
    internal sealed class AesGcmEncryptor : AuthenticatedEncryptor
    {
        private readonly SymmetricJwk _key;

        private bool _disposed;

        public AesGcmEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            if (encryptionAlgorithm.Category != EncryptionType.AesGcm)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBits)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(key, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBytes << 3, key.KeySizeInBits);
            }

            _key = key;
        }

        /// <inheritdoc />
        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag, out int authenticationTagBytesWritten)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            using var aes = new AesGcm(_key.K);
            if (ciphertext.Length > plaintext.Length)
            {
                ciphertext = ciphertext.Slice(0, plaintext.Length);
            }

            aes.Encrypt(nonce, plaintext, ciphertext, authenticationTag, associatedData);
            authenticationTagBytesWritten = authenticationTag.Length;
        }

        /// <inheritdoc />
        public override int GetCiphertextSize(int plaintextSize) => plaintextSize;

        /// <inheritdoc />
        public override int GetNonceSize() => 12;

        /// <inheritdoc />
        public override int GetBase64NonceSize() => 16;

        /// <inheritdoc />
        public override int GetTagSize() => 16;

        /// <inheritdoc />
        public override int GetBase64TagSize() => 22;

        /// <inheritdoc />
        public override void Dispose()
        {
            _disposed = true;
        }
    }
}
#endif