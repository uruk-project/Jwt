// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_AESGCM
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    /// <summary>Provides authenticated decryption for AES GCM algorithm.</summary>
    internal sealed class AesGcmDecryptor : AuthenticatedDecryptor
    {
        private const int TagSizeInBytes = 16;
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        public AesGcmDecryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            Debug.Assert(encryptionAlgorithm != null);
            Debug.Assert(encryptionAlgorithm.Category == EncryptionType.AesGcm);
            _encryptionAlgorithm = encryptionAlgorithm;
        }

        /// <inheritdoc />
        public override int GetTagSize() => TagSizeInBytes;

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (key.Length < _encryptionAlgorithm.RequiredKeySizeInBytes)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(_encryptionAlgorithm, _encryptionAlgorithm.RequiredKeySizeInBits, key.Length * 8);
            }

            try
            {
#if NET8_0_OR_GREATER
                using var aesGcm = new AesGcm(key, TagSizeInBytes);
#else
                using var aesGcm = new AesGcm(key);
#endif
                if (plaintext.Length > ciphertext.Length)
                {
                    plaintext = plaintext.Slice(0, ciphertext.Length);
                }

                aesGcm.Decrypt(nonce, ciphertext, authenticationTag, plaintext, associatedData);
                bytesWritten = plaintext.Length;
                return true;
            }
            catch (CryptographicException)
            {
                plaintext.Clear();
                return ThrowHelper.TryWriteError(out bytesWritten);
            }
        }
    }
}
#endif