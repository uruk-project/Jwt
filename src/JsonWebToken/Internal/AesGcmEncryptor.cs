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

        private bool _disposed;

        public AesGcmEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
            : base(key, encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category != EncryptionType.AesGcm)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            _key = key;
            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBits)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(key, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBytes << 3, key.KeySizeInBits);
            }
        }

        /// <inheritdoc />
        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            using (var aes = new AesGcm(_key.K))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, authenticationTag, associatedData);
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
        public override int GetBase64NonceSize()
        {
            return 16;
        }

        /// <inheritdoc />
        public override int GetTagSize()
        {
            return 16;
        }

        /// <inheritdoc />
        public override int GetBase64TagSize()
        {
            return 22;
        }

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            try
            {
                using (var aes = new AesGcm(_key.K))
                {
                    aes.Decrypt(nonce, ciphertext, authenticationTag, plaintext, associatedData);
                    bytesWritten = plaintext.Length;
                    return true;
                }
            }
            catch
            {
                plaintext.Clear();
                return ThrowHelper.TryWriteError(out bytesWritten);
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