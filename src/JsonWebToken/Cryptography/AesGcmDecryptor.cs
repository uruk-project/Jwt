// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_AESGCM
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    /// <summary>
    /// Provides authenticated decryption for AES GCM algorithm.
    /// </summary>
    internal sealed class AesGcmDecryptor : AuthenticatedDecryptor
    {
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        public AesGcmDecryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            if (encryptionAlgorithm.Category != EncryptionType.AesGcm)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            _encryptionAlgorithm = encryptionAlgorithm;
        }

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (key.Length < _encryptionAlgorithm.RequiredKeySizeInBytes)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(_encryptionAlgorithm, _encryptionAlgorithm.RequiredKeySizeInBits, key.Length * 8);
            }

            try
            {
                using var aes = new AesGcm(key);
                if (plaintext.Length > ciphertext.Length)
                {
                    plaintext = plaintext.Slice(0, ciphertext.Length);
                }

                aes.Decrypt(nonce, ciphertext, authenticationTag, plaintext, associatedData);
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