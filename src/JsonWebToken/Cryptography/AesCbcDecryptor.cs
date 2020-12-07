// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class AesCbcDecryptor : AesDecryptor
    {
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        public AesCbcDecryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            Debug.Assert(encryptionAlgorithm != null);
            Debug.Assert(encryptionAlgorithm.Category == EncryptionType.AesHmac);

            _encryptionAlgorithm = encryptionAlgorithm;
        }

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext, out int bytesWritten)
        {
            if (key.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (ciphertext.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.ciphertext);
            }

            if (nonce.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.nonce);
            }

            int keyLength = _encryptionAlgorithm.RequiredKeySizeInBits >> 4;
            if (key.Length < keyLength)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(_encryptionAlgorithm, _encryptionAlgorithm.RequiredKeySizeInBits, _encryptionAlgorithm.RequiredKeySizeInBits >> 4);
            }

            using var aes = Aes.Create();
            aes.Key = key.ToArray();
            aes.IV = nonce.ToArray();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var decryptor = aes.CreateDecryptor();
            bytesWritten = AesCbcHelper.Transform(decryptor, ciphertext, 0, ciphertext.Length, plaintext);
            return true;
        }
    }
}
