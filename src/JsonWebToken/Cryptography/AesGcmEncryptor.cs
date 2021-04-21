// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_AESGCM
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    /// <summary>Provides authenticated encryption for AES GCM algorithm.</summary>
    internal sealed class AesGcmEncryptor : AuthenticatedEncryptor
    {
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        public AesGcmEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            Debug.Assert(encryptionAlgorithm != null);
            Debug.Assert(encryptionAlgorithm.Category == EncryptionType.AesGcm);
            _encryptionAlgorithm = encryptionAlgorithm;
        }

        /// <inheritdoc />
        public override void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag, out int authenticationTagBytesWritten)
        {
            if (key.Length < _encryptionAlgorithm.RequiredKeySizeInBytes)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(_encryptionAlgorithm, _encryptionAlgorithm.RequiredKeySizeInBytes << 3, key.Length << 8);
            }
      
            using var aes = new AesGcm(key);
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
    }
}
#endif