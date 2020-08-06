// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    internal sealed class AesCbcEncryptor : AesEncryptor
    {
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        public AesCbcEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            if (encryptionAlgorithm.Category != EncryptionType.AesHmac)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            _encryptionAlgorithm = encryptionAlgorithm;
        }

        /// <inheritdoc />
        public override void Encrypt(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> nonce,
            Span<byte> ciphertext)
        {
            int keyLength = _encryptionAlgorithm.RequiredKeySizeInBytes >> 1;
            if (key.Length < keyLength)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(_encryptionAlgorithm, _encryptionAlgorithm.RequiredKeySizeInBytes >> 1, key.Length << 3);
            }

            var aesKey = key.ToArray();

            using Aes aes = CreateAes(aesKey);
            try
            {
                aes.IV = nonce.ToArray();
                using ICryptoTransform encryptor = aes.CreateEncryptor();
                AesCbcHelper.Transform(encryptor, plaintext, 0, plaintext.Length, ciphertext);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                throw;
            }
        }

        private static Aes CreateAes(byte[] key)
        {
            var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            return aes;
        }
    }
}
