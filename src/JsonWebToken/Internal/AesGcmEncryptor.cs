// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.
#if NETCOREAPP3_0
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption and decryption for AES GCM algorithm.
    /// </summary>
    internal sealed class AesGcmEncryptor : AuthenticatedEncryptor
    {
        private readonly SymmetricJwk _key;
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        private bool _disposed;

        public AesGcmEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category != EncryptionType.AesGcm)
            {
                Errors.ThrowNotSupportedEncryptionAlgorithm(encryptionAlgorithm);
            }

            _key = key ?? throw new ArgumentNullException(nameof(key));
            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBytes << 3)
            {
                Errors.ThrowEncryptionKeyTooSmall(key, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBytes << 3, key.KeySizeInBits);
            }

            _encryptionAlgorithm = encryptionAlgorithm;
        }

        /// <inheritdoc />
        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            using (var aes = new AesGcm(_key.RawK))
            {
                aes.Encrypt(plaintext, nonce, ciphertext, authenticationTag, associatedData);
            }
        }

        /// <inheritdoc />
        public override int GetCiphertextSize(int plaintextSize)
        {
            return plaintextSize;
        }

        /// <inheritdoc />
        public override int GetNonceSize()
        {
            return 12;
        }

        /// <inheritdoc />
        public override int GetTagSize()
        {
            return 16;
        }

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            try
            {
                using (var aes = new AesGcm(_key.ToByteArray()))
                {
                    aes.Decrypt(nonce, ciphertext, authenticationTag, plaintext, associatedData);
                    bytesWritten = plaintext.Length;
                    return true;
                }
            }
            catch
            {
                plaintext.Clear();
                return Errors.TryWriteError(out bytesWritten);
            }
        }

        /// <inheritdoc />
        public override void Dispose()
        {
            _disposed = true;
        }
    }
}
#endif